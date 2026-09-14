// satd status page: refresh the server-rendered page from /status.json.
//
// Every value arrives formatted. This script only copies each one into the
// element carrying the matching marker, with textContent, and never parses
// or builds HTML. With JavaScript off the page still shows everything as of
// its load.
(function () {
  "use strict";
  var poll = 5000, staleAfter = 12000, maxBackoff = 60000;
  var lastOk = Date.now(), failures = 0, timer = null, phase = null;
  var freshness = document.getElementById("freshness");

  function each(sel, fn) {
    var els = document.querySelectorAll(sel);
    for (var i = 0; i < els.length; i++) fn(els[i]);
  }

  function apply(v) {
    each("[data-t]", function (el) {
      var t = v.text[el.getAttribute("data-t")];
      if (t !== undefined && el.textContent !== t) el.textContent = t;
    });
    each("[data-w]", function (el) {
      var w = v.width[el.getAttribute("data-w")];
      if (w !== undefined) el.style.width = w;
    });
    each("[data-s]", function (el) {
      el.hidden = !v.show[el.getAttribute("data-s")];
    });
    each("[data-st]", function (el) {
      var s = v.state[el.getAttribute("data-st")];
      if (s !== undefined) el.setAttribute("data-state", s);
    });
    each("[data-l]", function (ul) {
      var items = v.lists[ul.getAttribute("data-l")] || [];
      // Rebuild only when something changed, so a selection inside the list
      // (a connection string being copied) survives an unchanged refresh.
      var sig = JSON.stringify(items);
      if (ul.getAttribute("data-sig") === sig) return;
      ul.setAttribute("data-sig", sig);
      while (ul.firstChild) ul.removeChild(ul.firstChild);
      items.forEach(function (it) {
        var li = document.createElement("li");
        li.setAttribute("data-state", it.state);
        var label = document.createElement("span");
        label.textContent = it.label;
        var value = document.createElement("code");
        value.textContent = it.value;
        li.appendChild(label);
        li.appendChild(value);
        ul.appendChild(li);
      });
    });
    phase = { dot: v.text["phase.dot"], label: v.text["phase.label"], state: v.state.phase };
  }

  // sat-tui's three states: the page keeps the node's own phase while fresh,
  // and says stale once two polls have gone unanswered, so a node that has
  // stopped does not go on reading "ready, 12 peers".
  function markFreshness() {
    var age = Date.now() - lastOk;
    var stale = age > staleAfter;
    var el = document.getElementById("phase");
    if (stale) {
      el.setAttribute("data-state", "bad");
      each('[data-t="phase.dot"]', function (e) { e.textContent = "✕"; });
      each('[data-t="phase.label"]', function (e) { e.textContent = "stale"; });
      freshness.textContent = "No answer from the node for " + Math.round(age / 1000) + "s.";
    } else {
      if (phase) {
        el.setAttribute("data-state", phase.state);
        each('[data-t="phase.dot"]', function (e) { e.textContent = phase.dot; });
        each('[data-t="phase.label"]', function (e) { e.textContent = phase.label; });
      }
      freshness.textContent = "Updates every " + Math.round(poll / 1000) + "s.";
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (document.hidden) return;
    var delay = failures ? Math.min(poll * Math.pow(2, failures), maxBackoff) : poll;
    timer = setTimeout(tick, delay);
  }

  function tick() {
    var req = new XMLHttpRequest();
    req.open("GET", "status.json", true);
    req.timeout = 4000;
    req.onload = function () {
      var body = null;
      if (req.status === 200) {
        try { body = JSON.parse(req.responseText); } catch (e) { body = null; }
      }
      if (body && body.view) {
        if (body.poll_ms) poll = body.poll_ms;
        if (body.stale_after_ms) staleAfter = body.stale_after_ms;
        apply(body.view);
        lastOk = Date.now();
        failures = 0;
      } else {
        failures++;
      }
      markFreshness();
      schedule();
    };
    req.onerror = req.ontimeout = function () {
      failures++;
      markFreshness();
      schedule();
    };
    req.send();
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      clearTimeout(timer);
    } else {
      tick();
    }
  });
  setInterval(markFreshness, 1000);
  markFreshness();
  schedule();
})();
