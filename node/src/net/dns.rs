use bitcoin::Network;
use std::net::SocketAddr;

use super::peer::PeerAddr;

/// DNS seeds for the Bitcoin mainnet.
///
/// Mirrors Bitcoin Core's `CMainParams` `vSeeds` (kernel/chainparams.cpp,
/// v28.0). `seed.bitcoinstats.com` is retained as an extra: it predates the
/// Core-parity sync and Core has since dropped it, but it is harmless to keep
/// (a dead seed is just a logged lookup failure) and removing it is a separate
/// behavioral change.
const MAINNET_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
    "seed.mainnet.achownodes.xyz",
];

/// DNS seeds for Bitcoin testnet (testnet3).
///
/// Mirrors Bitcoin Core's `CTestNetParams` `vSeeds` (v28.0).
const TESTNET_SEEDS: &[&str] = &[
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.net",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me",
    "seed.testnet.achownodes.xyz",
];

/// DNS seeds for Bitcoin testnet4.
///
/// Mirrors Bitcoin Core's `CTestNet4Params` `vSeeds` (v28.0).
const TESTNET4_SEEDS: &[&str] = &[
    "seed.testnet4.bitcoin.sprovoost.nl",
    "seed.testnet4.wiz.biz",
];

/// Seeds for Bitcoin signet (the default/global signet).
///
/// Mirrors Bitcoin Core's `SigNetParams` `vSeeds` (v28.0): two DNS seeds plus
/// the clearnet literal `178.128.221.177` Core seeds the default signet with.
/// The literal needs no DNS query — `lookup_host` parses `IP:port` directly —
/// so it rides the normal clearnet seeding path. Under a proxy, signet falls
/// back to the `.onion` seeds instead, so this clearnet node is never dialed
/// in Tor mode. (Distinct from the `-fixedseeds` last-resort list, which stays
/// `.onion`-only — see `fixed_seeds_for_network`.)
const SIGNET_SEEDS: &[&str] = &[
    "seed.signet.bitcoin.sprovoost.nl",
    "seed.signet.achownodes.xyz",
    "178.128.221.177",
];

/// DNS seeds for regtest (none - local network only).
const REGTEST_SEEDS: &[&str] = &[];

// The `.onion` seeds below are the Tor v3 entries of Bitcoin Core v31.2's
// fixed seeds (`contrib/seeds/nodes_<net>.txt`, the input to
// `chainparamsseeds.h`), plus satd's earlier lists, kept only where each
// node answered a version handshake over Tor on 2026-10-31 with the
// network's magic and `NODE_NETWORK` (#1162). Seeds churn, so this is a
// point-in-time snapshot; once any one connects, `addrv2` TorV3 gossip grows
// the peer set (see the AddrV2 handler in `manager.rs`). Before this, a
// Tor-only (`-onlynet=onion`) node on testnet4 or testnet3 had no address to
// dial at all.

/// Tor v3 `.onion` seed nodes for mainnet.
const MAINNET_ONION_SEEDS: &[(&str, u16)] = &[
    ("26jfbxrdnsbxlai7qonraijp3sa2sybizmx75ry6dyr3s3dampmwufyd.onion", 8333),
    ("2ca656itamfkipcwcdh3bpdbd5mn5xo5ii7vw3oawve44meshol6sxid.onion", 8333),
    ("2ezowyspxovboz4vh6gapgrum33exbcchfkczkdgwbwuuilg4eg6dbad.onion", 8333),
    ("2gmwpdjjjdjo4qnwtx3ywrxsxquwtlxr3okxq4l7mieym34qv4x27lqd.onion", 8333),
    ("2l465kxadtqllf2wxledetrz4d3ya46zkyw6zy3vyjkqqnwls2mvtyqd.onion", 8333),
    ("2mgi53r3olnwx7sgpfnb5xpkvyl3kayii2gvel4adfwaglkiwsgwamqd.onion", 8333),
    ("2ptbjwtj7bi4u4jcifnawrkrli6yqbsnncpftla4nkuzhyvelvuwg7ad.onion", 8333),
    ("32djhc6hjaff2ohueoytojgahm4f4acij7hmcrlyjeattar2ihz35uad.onion", 8333),
    ("35kcii6eyanzvlbitmgxd6gmpanuyojib2z6rcwptbbtrnl5izgxrxid.onion", 8333),
    ("35lmqbnvj5cxmiewccr3ui77pjd7bftlcfxrpw5os4ukxgsv63hkoayd.onion", 8333),
    ("35okkasj3syxb2zwnlp6k2bsjatfhovyyvzgld7acoryjd3blz4dxbad.onion", 8333),
    ("3cu7ae4jil536wjsdqjdpet5vfdgocip4i6azaakxjpeiuhe5vqwsayd.onion", 8333),
    ("3ddlxdzl4sbzqnxnuasuovtvevsmmxqlh6koamn2y4otoykuk2mdzuad.onion", 8333),
    ("3rx7ekxlz7win4wke62j5sk6pxft6w7aycazbfxhixgqvku5cbxc22id.onion", 8333),
    ("3xjuckzzvmh6yewxnqggsohws77dqnhwmdrqdc6itz42tkb4o3tpdwqd.onion", 8333),
    ("3z3zwvf4geonjor6w4ulv2243hpccai6u2iri4nn2tb2674y4myhf2qd.onion", 8333),
    ("462llr6zevwmvkuhsercdigxu7gy3rt6hhcjij73a5nbaxmwq4z5cpyd.onion", 8333),
    ("46cl6zhwzsjxstkxrljpavd6f6xlomyeitoeax5tj32p2voaxgax5uqd.onion", 8333),
    ("4jg7uabqh3zsprvx7zubkilbjylllcifvnlmnqeqxbticupx5lyzduqd.onion", 8333),
    ("5jw5x32jypyivibetbie6lkmxshoduz46auota3w65qptpthsdg7apyd.onion", 8333),
    ("5lnzkfqlq56mpmxkstef3xj26qgaa7bu4bzvfs5rfwgrvr764bfgmxqd.onion", 8333),
    ("5pewkpzkmxobeese64uinpvwnlcitokutllxaii6jptpqqkuelvswtad.onion", 8333),
    ("5pjnfvwjawegbdffowe3estdhcbyo6dhtepw7vzc4eq7bxz7tuo2yjid.onion", 8333),
    ("5yqo4k3ilzbvygfzspslh3sye3d3h27ewbd736oj3qssoe3jgq7jrgqd.onion", 8333),
    ("5z56m27m73te57egak7ulmgcw6b22vryp6eawlx5lxghx5pto2lccxyd.onion", 8333),
    ("6c4zr2uzyubml6dcyrr76fptd366oajrh4uezksbbs36x52szx4lknyd.onion", 8333),
    ("6xxntj2njzgfcow3z3puyhcsl7ewe4lwgtqndso5djnd5jp7ivrvhoad.onion", 8333),
    ("74m3lpfqc55v2yrjbtgldt3jdrg4gdelhiaxe2ijaqypjk2l5gtnrvid.onion", 8333),
    ("7fpt5pv6ywtkdoakyoktyqdnqlycjlpkjwsz4nposnng5ndg25hwr6qd.onion", 8333),
    ("7wl4hcvrqmd6zd6477k4phjx4kxos5ua7lnnysvb6hdcwwqintearoyd.onion", 8333),
    ("7wt2hx3f3ci7uwn6w4csly6cv7l7qfm45b37fw2mv7qfrykdcy4vuwid.onion", 8333),
    ("alpomv43bt4yb4i63wkajueoafvjgruetfcq6emnzfmda3c4etv2gsad.onion", 8333),
    ("ayqofpmapnj2yyslsq2cqlzriaune7fzpnwpzb3ck2ucods7r5egjcyd.onion", 8333),
    ("bt5xf6afgdjh7hyeb23jcnwoipz2s7dartjzcrxvlmxujbddvbrv4fid.onion", 8333),
    ("cfee34r6sb4qrisyo7t44uozjvyfajocq6atl7htdarn3tgjxl635jqd.onion", 8333),
    ("coxlgfjherkt6w5f6h6z642epurvqnv6vsw2bm4gdrg6gtmcle24ztqd.onion", 8333),
    ("d73r5lnznhwk3e7xbopx3ic64zwyvmzqyted7kt5isiqtootqqzv7nid.onion", 8333),
    ("d7icsp7naafsooy3jdalxqeqypfow674hzmt33z3zcvr7m6ohynbinyd.onion", 8333),
    ("dczos4uwxk4zrnqzghekfwwfn2xoobjf46zi6tscyjisef5sqvvdzcad.onion", 8333),
    ("dfm5ov3kmcc542ynj6dmvhoekqnjpbyt34auun65m34fampx5ckzwhid.onion", 8333),
    ("dg7eht7volybfe5ksl7lg2drho3lf7fa3p66s2ivr2xida3fucc6urid.onion", 8333),
    ("di2vurmytyvaa223vkoeekj2rkctiuufkgrwkzf7pwnulqfie7r32eyd.onion", 8333),
    ("dxtynfs7ez367vemphccgumy3d3ke75aim4zuv56ytry7mcnbfvrcnqd.onion", 8333),
    ("ehdxwh4z6gx3kmzuo5s2okdip6mjdzjkjsmnlyf5oxaslnrsvumus4ad.onion", 8333),
    ("elba25chv5x6nolo5332ua2xkkb5d34prt6tmtl23vljc76wgikh2xqd.onion", 8333),
    ("eohmgcepxqe5segzfdsgsdtvbdgvgc6od7fbidcnqas4uppjf3i3wrqd.onion", 8333),
    ("eqlgno2eibpnsk7lajkint7ft4ol43fxqiadtlpvpdav6x76oxlb3aad.onion", 8333),
    ("esbhnxhmsmaul6ecnvd6kvndba3t2fl6mq5npxmfhpfcce4ls5kmread.onion", 8333),
    ("eygz4x4vgnjbsnwailoupv4ziv255tubwr5wv7u4hhpntdgevbjpx7id.onion", 8333),
    ("fbbbf5i2hhkn4h6meyrrsod57sufmw5a4oj66yndstjnmxg3c3cwafyd.onion", 8333),
    ("fk7s4uml2z5pvxgoorkkgcjw73lqztkj7dkled2dsncuzkhvqzsjcayd.onion", 8333),
    ("g32e3acmzyqekmmfdsnqspspjeyw2uhdmmjpqkydjsslqkeipfnqntad.onion", 8333),
    ("g4mdqyy5kvkvfnfbwouuw3rnhw75hx3ragqizkat43nlpmc5wsllfoad.onion", 8333),
    ("gmc2dhkjxmlibkr2ka2hcqy7xfbnccfu4nnvlolq3m4kycwyjoikm5yd.onion", 8333),
    ("gqzuercqjpx7kocl3o7bmq2lg7bvfk2qwpr65x57nuprsvunyhfjzoyd.onion", 8333),
    ("gydqmwdrz2ly3uxkjbjrjkr2336zrd52irqh5tadif45s25riunsk7id.onion", 8333),
    ("ha5jjdxx5ugmsi35ugkxjeogpksslao56bky7fp24xztlv2aoqhbynid.onion", 8333),
    ("hbxqnq7y2bfb46dvkaedgcgb5qha2omsljmsrfogl6bu4sffydnxomqd.onion", 8333),
    ("hgdyatewzn635qcb5x7wun7j7rtlplxactibeg5ht5xhl4wimem35zid.onion", 8333),
    ("hwydtfysaq2dhi7n7gd7nmuweg3v62vzo4xnekaxeottoeyp6r72ayad.onion", 8333),
    ("i3zkwfuni7rmfugnxisnxqtsm4j4vuwubuebmpaaqsmrr6uq52u7vdid.onion", 8333),
    ("j3evn6bkkm74f7inrvqtjuxo47ia62hrfsnjbyhazjpaz7q3hzosurqd.onion", 8333),
    ("jks32aib2ebuzpze6slsrlqwj2nektd3a64tf67xngmvkdtu3rvklryd.onion", 8333),
    ("jltlsk6mvvwyk27cuwfzvbtocgg2hd6jzg5kuknnvrnsokpw76s5nvad.onion", 8333),
    ("jrbnukzzpexnxm4mpdbjaqgrh26pl65brqe25adac5zwubuvfss4ilyd.onion", 8333),
    ("jwoplqt3mvi7uszbt5ycnh2wk6j6e3vowrat7fmwbbn24agwovzqhuqd.onion", 8333),
    ("kdhjyaqu5cgrlw2hdhc2a4rjzn4pukqvtmy66al3u7ml6t33kb5ti5id.onion", 8333),
    ("ke736kvql5jfpc5kxeaepvnu7ysjuyslrsabbypx5pygvmugewuo4pqd.onion", 8333),
    ("klhz4njqsy6dob7vu473nvquzvaupzng7mttgyxz4l2evuxzpavlq4yd.onion", 8333),
    ("kmas6z5dnwg6vs4czqm3o7d3lcs6ihqiamxfue5irch72d25yjbgjead.onion", 8333),
    ("ku5vzo4wyprye64cdsqxegygvquhxu6glzk6mbuqhiilgpe7xzlv2iad.onion", 8333),
    ("l5b75umcnrjo2q42emfkwkgsb7maee3woou2nz26sqw57vxaczi6vvid.onion", 8333),
    ("lec7f3iaa6phcjgtxwdcelmnkoc3xgyfiiui2ytcjd5zd3o2gjb53pqd.onion", 8333),
    ("lvl4u4olowvqni7exa23ourvsvaifsjbsinqm567652cwq3gf4nxcbad.onion", 8333),
    ("lwa5jhnrhaswseiert3jrhcu6at6rs4dj3rgvbfvcv7yy7tnv73rerqd.onion", 8333),
    ("n2snxkqi2ukxmprp6xdxgluekiwa47rmfpjlwu2rji4os2jgqv4huaqd.onion", 8333),
    ("n56w3dulod6mtfhit2jufyhyynfiqrp5dfnlpintbg4ptpfj2rlf33id.onion", 8333),
    ("nismz4n6za3qk7tq5kxg5ccqzd7oytqpsqkalbqgg7w7miszcyoccyyd.onion", 8333),
    ("nttkhv4xc7cqwffpdoenghpo2c7kzzgm2n6w7fqtjlvhm6yt5vxldbqd.onion", 8333),
    ("nttzhooizmzgtmmoiekdcrkpah3fdh6bjhlsozudzyj42qk3uohq5lyd.onion", 8333),
    ("o3znpc65ata5qtnpxsladsi5cjnaagvazwmju3yr4uywldbosayezdqd.onion", 8333),
    ("oh2zlcpuu7kohkifsjmdrfptzchox6gabqwd45zmmtagbdutsju5v6yd.onion", 8333),
    ("oi7myopz4egfch47gdhqrawhqyjd7msnbvmebxlmwkxj2oc3v7jgfpqd.onion", 8333),
    ("ololrmd6nhdoagjzpfbdbxwcln7w6xbgsojngq2u7vs6i7fgbl2dacqd.onion", 8333),
    ("ovt2cumfgbf75h67z6i5t5xq6wxhv7k4obhp7z7hmhfmo5e5pb3m3rid.onion", 8333),
    ("pgghugjycg5gee6ebk52qcjxnrgvpo6evksnz56ldisom25ieg6yjuid.onion", 8333),
    ("q5auzukt3wvmm33ggcwr2ajya2cwwlu2qfegcsolekej6vl3dhh7slid.onion", 8333),
    ("qhvkfr7ws454yzil4we2z43pgdciaga7xiixzi2kwwab4pkgrppdzvad.onion", 8333),
    ("qsauypffrmupw6puuoemfr65uyqbaxuyfbhtpzyc333o64lvwaiaywqd.onion", 8333),
    ("qtwmgohfnmislgcndsrs6occpcbcfogvvlyp23yv4dx4fr326vmzw7yd.onion", 8333),
    ("rhpozy2z5ut6hs4ukawjej6sn5vfqrsc7z5i4u6b3rtgv7anlmybf7yd.onion", 8333),
    ("rky7zz76yvft4ofwmkdsprm2b4tbqxygxxqbvh4s2erhrjelr5wgcryd.onion", 8333),
    ("rpv5jazbjgdxlxblvknadzu5sw6swlrs7sg6jsfpipjjg3omjxbz4cad.onion", 8333),
    ("runbtcnd7trpbqkvqa4qwg2s6cnlnyc2ajxk5nxh2znk7fkrphysn4ad.onion", 8333),
    ("runbtcndu6cirobkbrpfr3lyagmokzuvp2bxep7thzg6pdmn3mir36yd.onion", 8333),
    ("rvkxwfgmnn52ubmyase7stexaxmq2mgeatjiw4kbelvqliq5nycqvead.onion", 8333),
    ("s4ycyfms6rgyaovivdqbyttmf4nxmf4xx2rnebzjlm4iuzh2frvxjaid.onion", 8333),
    ("sfyy2eqfn73did7ab3xjdr4nbp32kpsduhn342iah4peq5xy32e33rqd.onion", 8333),
    ("shame2rrgqa2fq3esx4zudeerzpx4vzvmbjjhbclbnalxsluc32iikqd.onion", 8333),
    ("sixrzjq7fnl2h2cvidvfii2z5yuvmcobkp74boffwc62fv3px35svkad.onion", 8333),
    ("stw2v772blji7h6wc5zss5mjexzjc6fukpni3jbp3llodc2a5apqyoyd.onion", 8333),
    ("stxz5a5n7lvro4jda2ugr4i3ufnhkvifqdw6c2xverdlipsrgonek5id.onion", 8333),
    ("svezmh24cgqujtbgvp77rbutwu5b5detv5zddah42i7hypwqu62cvzqd.onion", 8333),
    ("tjeiksr4gizw4jozvyilivrhd7dbik4asabja5nsc7j667mz4as4rhyd.onion", 8333),
    ("tostega5we66duknqueqsgoxqokekwim2itgpktwryhlzdemwwcdhqqd.onion", 8333),
    ("tw2gw2ownxt4a6wz534j74abjr3d4lxmxdsinddanh2vyys4ct4e3had.onion", 8333),
    ("u2t3wm6qeivpsglk5ejk2mlmnykofv6nh7rslr3xhbtmeeuywefoosqd.onion", 8333),
    ("u4dmemh54dwnagcn3s7nnfx4d2dhst4mnu4bqjzrscfuxujct46i6jqd.onion", 8333),
    ("ugrktq7cvbxuiairsjg355otgo6sj5o6v4tdh6jgyfzhwot6hdk35vid.onion", 8333),
    ("ugymttztvn2phtt7kri27znqce2ygztwd6esmnkhrdr666uoqsmdtxad.onion", 8333),
    ("utroczdxvnhziozke5vu2mltn2nylckicvu2teyrbiujjzwbwzeha2yd.onion", 8333),
    ("uzjmlb42mhl45ld6awhvk6pwdqif76jgzzq5hsmuk5pqdlzqawu3rsad.onion", 8333),
    ("v6dk54o7eqt3qu6cyfh73whi4yojqfvljeric7a36bpuy677wzxu2hid.onion", 8333),
    ("v6hdsumwmt72iecmhfpqieakg6u37t5yl6vzrzo5wzejmwv7ajnn6lid.onion", 8333),
    ("vkrylooy2kphnalj743mhqobudi7fy3u3e2d4smluzmz3ocat7y3bpid.onion", 8333),
    ("vmfpjx66xzxjou3feseelc2bvtd2rtxzri36odg66u7nfbrb5bew2pqd.onion", 8333),
    ("vqfiycyhxoh44hciaznjyeasgevc7n3ht6sbo5ifbdazxyflq6xoidid.onion", 8333),
    ("w3vecku6tbnlbxkhlauw25eh7ra2h4nfhxuozgmfzshwlz47bny45did.onion", 8333),
    ("x6phkjxljpaxadss27tacebq4n4rgmothga4xvrdxsj5rxst2kr46uqd.onion", 8333),
    ("xdsiekckqa4phxh5a3jvji2cicr2yr4hyy3omw5x73u45ipn4ajwdxad.onion", 8333),
    ("xgoidfkdv43ogx3pzczcyjfzjjjnj4it7ssyuehqddcynl2chn3ahmqd.onion", 8333),
    ("xj6ud77fdqlal7vpapmgnnpkzxdyiqlh6dq3grcxlittx7yvjwd72lid.onion", 8333),
    ("xnt4oa23anc4hvsspz2sq7x3jxinqgr4j3ckj632akjpohan2p6vfhyd.onion", 8333),
    ("xo6d4upsa6gu4ngxcekp5b6czcbx5ahuc5xajji5t5khkmr2b7ca5iyd.onion", 8333),
    ("xogn4krs3iklbqdvrbztkmsxbyxyq4gncdosrudiwblob5qf33zpsvad.onion", 8333),
    ("xtvkcpef4wsn2ysquuqohypuheko3fpwgyustgm7fsh5zk2z5w3wkqad.onion", 8333),
    ("y2iaaicvyvqrt5gnqngbna2psl22c4zwvkupdzkxp6ysjeep74sgtdid.onion", 8333),
    ("yadufpjilf7yflt7p4mmfi2xrjqipf3dt2njall2w4nkvz2jqyt6j3ad.onion", 8333),
    ("yklmuva66pzp3o2znx5mkzboic6fm63pt5katvmbniok2fvo2yggf7qd.onion", 8333),
    ("ypy6l6ifrdl4kfxfgvajji5fbscozvp3fuzjkb3fslr62on3fxh4s6qd.onion", 8333),
    ("yqdsywyf6bict2e2jebxm7j4nhdikaswcalh4cbzgqk3sm44qzoh4aid.onion", 8333),
    ("ysj5dkk6jxj3cmdvkakl4ex743dudy3xuu5yodltt5usufp5cf7kmuid.onion", 8333),
    ("yvnxxe3ghte7lsz77izb5uygzgi7fyijhqfhvdzjhzkgakr5tkqydrqd.onion", 8333),
    ("z4kf5t5rvcv6rssyp4tcr3rz2dfpowlp4wci5tnouzpxkxofwutnw3yd.onion", 8333),
    ("zjff6dils67uzfbfflojgjha2qrscjbdx3xl33qxbu6s7ukcawnmytyd.onion", 8333),
    ("zqm2s7pvssxlcbw7qqpb2jqgbzgy2jpz2ex6gghyazlqzwk6agcw6nad.onion", 8333),
    ("zrggximdixhwt62lqktar4mjum3byusx36dc52kyqsv65apsmztabdad.onion", 8333),
    ("zxx7rf4a44zjqrk42pq2ifygado7n4mc655jgtutkyyifca6z52xwcid.onion", 8333),
];

/// Tor v3 `.onion` seed nodes for testnet3.
const TESTNET_ONION_SEEDS: &[(&str, u16)] = &[
    ("3dt6kgfrilc3nwliwy5wbmc6oa2b5y3t33nkxlrxrkunr2hoaj56kgyd.onion", 18333),
    ("3rfphqncnepbm7tvnaqjetkaqvauj566nw3ys27fert6zx3q75zetoid.onion", 18333),
    ("3vnbi5o3hyzk4cm3hhnyo3h7tclr6pybmhmqwkbyclslfhqtg72pq2id.onion", 18333),
    ("6fdbuqf2kgeweeoeikmwfezauys657lzezzus4nxmekkumouptg5ezad.onion", 18333),
    ("aesy6tfufadkut6flu2bsqgnw2422ur2ynjalguxlzuzuktg3zehttqd.onion", 18333),
    ("bizdwmm7naqq5pehkbfggznqtena5eodz3kprvsbj4nkkax4fvxx53id.onion", 18333),
    ("bjqttlyt5kxcn7sitpiavf2cuhdf6rlwigericlh7um7gzkqyyefqnqd.onion", 18333),
    ("c6pk75ti4mjmoumlnxjwrcyr6u2qoltf3ywk2odweupz3sr55gqg6pqd.onion", 18333),
    ("dskf46hfkefyr6nio5gtqp7em7rh6aqwrugdegfooaoxcux5ym6bkuqd.onion", 18333),
    ("f472j4pynbgltb63mr2lhyvhecfqdjdcfmr2s2id4rreemyn32xtjuid.onion", 18333),
    ("fl5wdp4jleymf2efplmos6hbj7py7nvwaps2yzfa6sfhvk6e7bd4umid.onion", 18333),
    ("gggan3nuzxpd655lafnsunqfxgy56bvsxuuzucgmaowyvq3d7a7o7jad.onion", 18333),
    ("gsw6sn27quwf6u3swgra6o7lrp5qau6kt3ymuyoxgkth6wntzm2bjwyd.onion", 18333),
    ("guudgx24aokistytvm3hj7u5cbvdkr2b643r5t33pa536ekfn2lfykid.onion", 18333),
    ("gwtx5qluopwaxjhedlifnr6pptw2eihojzhq3stnv2gfbvqbgqdhi5qd.onion", 18333),
    ("hjwzovgwou3py6ncemgmzpvcihay5cuzuxvqdn74axndmll25p4mwjqd.onion", 18333),
    ("iradeaffnpqfhkuo4rqbq5dgdazymxyjifeb6jz4yq7rgqhnsflfhzqd.onion", 18333),
    ("j53y5paeb7xcrptntut7epccjglduquldjlzjlho4lj2msabnygrljqd.onion", 18333),
    ("jbgve7zi4vx5l7654ih4nzutspu36dvs66xlegciur2cpym4gdjigbyd.onion", 18333),
    ("jtvqgaccxbtzshtulk5xlsb4wkoil3psmpn5avqyp2i5vm4hqh5cicyd.onion", 18333),
    ("jun6gdmbgasr57bhr4zs3dfhc6pzpaw27nqb4dadbai7yrbq55zskeid.onion", 18333),
    ("lh3wfz2n7xe2muwdjrz5vgnjwjx7lc6iifojhr2rh53ojkwo5dr66uyd.onion", 18333),
    ("lka74booetkbmat2q64haawcytbwx7mnctvo63ww4jgi4yuqnl6p3kad.onion", 18333),
    ("lwfecq35ocqjfbdq4h2qmcwl3cfcyiyycxtvrz36ihdbuczehi3bmrad.onion", 18333),
    ("mdj4zxy5afohbhm5qdwcbzzpqsdi5w6ur24obkkjcctzj76dgtkedqqd.onion", 18333),
    ("mh2bq22jchtolmufub5abodq2l36kmrg26owlb634hsv5h5eagyuekyd.onion", 18333),
    ("nkqgfcw3esmr2nbflt5h4zhfhrzqh2txoh2crq6cyq3as5dra7m4vkyd.onion", 18333),
    ("nyrekcbm2ici6wv2umogtmwg7o2ivu4vm7bpcge5fayos5l377zldlqd.onion", 18333),
    ("o3zwhskjvuzbti3su3kfspgmvwoiq5iqw4drgo6jv6ehv2zfoyyy5nqd.onion", 18333),
    ("o4zdqfdoe4jfvn35twqtjkzmptmk3bsg45sp46wuxanceg3euqtwdjqd.onion", 18333),
    ("ppe2pepzphox3swftj5lbyi7ckigspbih5qnyuhrb3r6bn3g7k7bp4qd.onion", 18333),
    ("q2kkfl42elsu3f4c4yqxbgqc4tn3khtwdomi6ofznta3d22iits4i5id.onion", 18333),
    ("s3bxrurro4bmvsmntw74qf4vw3xl25xtnvqegayvlwj3b6t7d76kkwid.onion", 18333),
    ("t6hfkkujktjyzpepmphskoaivflu6fieyuxrshxfzwriwvoa2uccvvqd.onion", 18333),
    ("urhagmjceyqbzhjitpa7j7mygivxw3wlwqzkibw6zezrxeantkikgcyd.onion", 18333),
    ("vctlwaqgmu53eutz2hewuakcipfgtyljsd7czut4dd62xr3rp6fqezad.onion", 18333),
    ("vi3z4khdvopuiljdjdhpetnxztuzsct2aacuzcm5ba27h4j3cfwsvjad.onion", 18333),
    ("wgc4wp25gtnb54vd7x5h2xtetzrdoiizeyyh6fv3vxzp3bbalejbd3ad.onion", 18333),
    ("xlx7k5qzawdld5xcfd5lhhasp5tiklc2z326lamcnkmoru56jv6os6ad.onion", 18333),
    ("y4blifygwjgepjmnr6wlbqpgies4c2bdudifcfbplqnbjwzs2zrdnvyd.onion", 18333),
    ("zsmxmusdzrcqusk5h6syfq6a3ph6lwx3wpiltun4dmkrt3pa2fp7qaid.onion", 18333),
];

/// Tor v3 `.onion` seed nodes for testnet4.
const TESTNET4_ONION_SEEDS: &[(&str, u16)] = &[
    ("2m4yjmxoamgtzskezmaqwrhfi5hnnzehv44q3fj3ryjwhtz5e53cqmyd.onion", 48333),
    ("2sltzrq7ts5t4il5nimp75og2jksbwdjmgbdykz5ljeoqrxemzlakeyd.onion", 48333),
    ("4uzerod2wrqtjuaea6vr43uddq2sg3cgfuk4khqotqsqdsxpwdmcphqd.onion", 48333),
    ("5fkz5ijh76cgfwvxz4pyl4br4hekqflijz7d467ldey3xme2trqrgjad.onion", 48333),
    ("5rh3ln6ypycmn57qlmke3dliffg2id3ziz4dhsujng4tk34oklnbqtyd.onion", 48333),
    ("5sdzs2qu3ygb44jwo45y2kmbnqc6ijzpndaqn43zgngsiwq7mx6b7yyd.onion", 48333),
    ("5wpcussznj2dg5222zrtfdsx5ttco6xlv7447azzaaywu2t5xukqcaqd.onion", 48333),
    ("6g6dwtby74ic2ggnzkbfqy7saslopho7or6z4uad737c2tq24fj3ltyd.onion", 48333),
    ("6po3e27t4nxgls3mwnostpy47crhtc3ae6fcsn4yyfh5dfcaq3q3q3yd.onion", 48333),
    ("7jd422hqevrz334ax3fh77wzww7clnr4kpyos25oe64nifg623bjqfqd.onion", 48333),
    ("7kwh7rg3a4e5lgjvybesixzhwzxvf6dqo3gc4h7k5vilwmdjvtzidtid.onion", 48333),
    ("a3aej552sklp5nhrosr5wv7qylgkmnu5u7zh7se56vtllvhgctzkbjqd.onion", 48333),
    ("a6yijgwn4vtmmhl7uybtbuyvtl7mtj7arld5f4csqsx4syeii4gt3vqd.onion", 48333),
    ("aqabn424rm7qq5faw2ecckkzxfdw57oncivjrurrrn5wgjdqjqxvxjad.onion", 48333),
    ("azccjliswzu5aycse7g7zu2bw3mqicd2mhszczitp332scjgltehrjqd.onion", 48333),
    ("bv2uuihcluruxlt4zwedditinsjberjtaj7yciwd25nrhy3ufh7jjvqd.onion", 48333),
    ("c7nbt6bs5c7foimwc4wmwlrqd7fg22r76i22nglv2inx7tsav677gzyd.onion", 48333),
    ("clqr2to2r6fn4jo6f7xy3dppxgn4ewvnmwbxsdrrhnesyacmw5noaeqd.onion", 48333),
    ("dnshzxr6osjf2l5gjsbattjtoefgkzmd3p3fdyatr5ltz243zspsilyd.onion", 48333),
    ("ebhtfcmjhilcqtuls437pxu65dznqkpt5qv3yeq6zipnqd7ichz5htyd.onion", 48333),
    ("f2tt2hdbqlbslvdlpworasoijtqfxlkkcabl2kbu7gptojc2synwq6qd.onion", 48333),
    ("fsijrllgzgeg4pa5ebq4qy3swmplxkzvuvji5swt36quy42dznq3t3ad.onion", 48333),
    ("fwsrcrhnggi3qy5rsfiad3cwep3bf7uovcupgockbntjcfvoqxzr75id.onion", 48333),
    ("gc66muikqqzxwj2tdvvap6gpcbitthjvscawgkclim4vgmajrccjtmqd.onion", 48333),
    ("gsw6sn27quwf6u3swgra6o7lrp5qau6kt3ymuyoxgkth6wntzm2bjwyd.onion", 48333),
    ("gujxforhwszry5falvnarfcyajjxxsuvqevx6gk6meou5ordrxw3mdad.onion", 48333),
    ("havkohvjhg5tglbdecf4ufhz5es3f33ctj3b6loebj4pi6qrtjemfbyd.onion", 48333),
    ("i22efh4itlcfthvaavcz2rvigu4x6jqvlwuksz44bukslhg76bsgrxqd.onion", 48333),
    ("irwyrdkcrcdgwtsltcrqexqylwc3ezjhhra7u4i3gkwktezcut36buqd.onion", 48333),
    ("jspxdo33gyrh3tewi55mn2fo5spczzgipq6ao7fa5qu6fj2ezr7bizid.onion", 48333),
    ("kf6q2wza2ebo7cxln5ejcjjwvrew4vb2hf4vd5wo4nyzbnjv3yccduqd.onion", 48333),
    ("ko55e2ityiaqeckthmnnbcv6bbwll7rtdiv527muoqdpg4hye2it2pyd.onion", 48333),
    ("kolvizpy2tctu7tyq5qlquodwcsljtfbmowcxqsihfrlvwlihpsijwad.onion", 48333),
    ("mavvwxts5f3axuz4cyjqpz75veijkdkdueavekb5hia67zk257eg7tqd.onion", 48333),
    ("mdiwdijucocysdvx5dk2iyo5wsav3ehyiggegzfk3ezfcce6nstp4nid.onion", 48333),
    ("prilx36yi6wiz4ll77tapskzwzh5onphrnn6w5d56zrzdat4kjo3q3yd.onion", 48333),
    ("qhzfac4qvomln4ikp6xgfwgb2koxdgjsbeut3iplvsu5o33yf4ewf2ad.onion", 48333),
    ("qmd5qvyhnanqj6wyf4klrvfqoypuz6xjajhx2n272vr5il7nlwyoosqd.onion", 48333),
    ("qmw73e4zh2i6pvmlgx5642vwtynibghgvjdoox574hjxxv7fvd2oxyid.onion", 48333),
    ("rb2ekvp77t4hhhipt7dfuriwges4efybffrb5qurk3xrokgo5or5z2yd.onion", 48333),
    ("vfqxysj7olxstghkohezoembjnsyvpp2ph7kc4jaatvszyx2ajz627ad.onion", 48333),
    ("vh72vs4kp4mf4c6dopdprfavuuuq56vgtltozx5qik7awvy335h7btqd.onion", 48333),
    ("vizb74h32bx3u6zksgsi6seq6hcqdhok5pd4z2x5yj3ll72tu7pcu7id.onion", 48333),
    ("wkvaxtftpwmmvrptqavx6mwhrcwiecbodtshuenvot3cjgxsycuurcid.onion", 48333),
    ("yiolb6ahgjry66g3vt4dtlnybhdgy4udakakbjxuekj33ligd57mdlqd.onion", 48333),
    ("zdh7vrzykdv7474yioe5jiv3kgajky727t5phxsbt47lefjseo3ypaqd.onion", 48333),
    ("zjttaesjhj7ail437ag4emdufr775h5rtgoohlbca5rwc4re6dr5k7ad.onion", 48333),
    ("zmd4eq6svwn3qgm56dyodktagzi3xo4smxebgjdk2jbjkbmvn7gjm5qd.onion", 48333),
    ("zu3gjmendiuoogirxm6udfpympmchh2lxl3aeifzu7ahyuas3pzkgzid.onion", 48333),
];

/// Tor v3 `.onion` seed nodes for signet. Includes the node Core seeds the
/// default signet with through `SigNetParams` `vSeeds`
/// (`v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion`). satd's
/// other earlier entry was 55 characters, not a v3 address, and is dropped.
const SIGNET_ONION_SEEDS: &[(&str, u16)] = &[
    ("2uqd5pbaxn26o7fl7nqtm2khetqocislppxtxrpqg55wtbcqdrf2y5qd.onion", 38333),
    ("2ycyu2aba3xsqjr35beqporp5f64ntqs2sau2amn5ztq4j5q76amhqyd.onion", 38333),
    ("3qeedpzgciv65tdy2tsdmjxswhyep4aj65jtboznf5nnwcyo2lbmiyqd.onion", 38333),
    ("3xvum5nnvcchvfxwlbc2it7nbfxhml6ovt7xehjw2potempk2om4eoqd.onion", 38333),
    ("43nk7wpojel47fmc2il4sunwkpj4d2sh5rpeconlymplvuf7mwvnidqd.onion", 38333),
    ("4jbenbcdlfoiauayz4bdpfueobo3klbjtmdkbnwojq2awhhl74ngbkad.onion", 38333),
    ("6fy45vxzgc6siecr7en4k6oft4k4ix47jvkxqyzopalzwyphqc3hv2ad.onion", 38333),
    ("75ucqkuqndevjaqjnyfgyhzdfgcnknr6ki3skvkqjlxnrcfqc6wxqbad.onion", 38333),
    ("a7mvea5xgpknsqaifyvfstdn2utjvph564i6ti3nbdr2cksby5jhykid.onion", 38333),
    ("b3sbqhjstq34ae7lsrw3syhxcjdu2ssuf3f3kvbnyrvbp7cvuuopmbqd.onion", 38333),
    ("bxc4ubehjtw4hl7yfz6erdok5z2h76s7f7jlx2amtzxil2fxxcm64byd.onion", 38333),
    ("ckbugjazj2iotosxah7odbxfozxivuk6zu5npf3iwfphvoh5brdjfqad.onion", 38333),
    ("e6xhvtrt2ppjfxckbinu7a4jxmy7usjnvjx6st2cipmvlnnhxg7krbid.onion", 38333),
    ("ecx2z3x4nwbzjh6dh6vyccljkhnxya2o2o2tz3pzvetxfjjmujxhctid.onion", 38333),
    ("ejgeimjypsfuijpxzy5xpwmmjmkr4izwze6od5pw74csjglflib6nsid.onion", 38333),
    ("evesnuatxlbwi3soc3dq7ebxgpsn6apluntne4smlnuepdbax346f4qd.onion", 38333),
    ("fo7cekwzd3ibyoxuo53mfqoxffgfaupg5ydxbl3rofvwxtzbvgy3ciqd.onion", 38333),
    ("fqyzt7wikf6g6yxu6i2yar3lkqxbf6fu3c3pjnbg2oibt57usfmq42id.onion", 38333),
    ("gd4gyokpcnnqqodklhltjimcrhhmqj7otwlzrolw76aag4leqsyolxad.onion", 38333),
    ("hztyx76iaz4h3emavmzbuizqfg3q37ehfwr2k3afadtcmcepjsxhmeqd.onion", 38333),
    ("immdwqfyz2hhcmxmyypstz7syq2cygaklr43mqjmqefnmtcyuspwkbad.onion", 38333),
    ("jgn75dy52o2lt5wr5qkf4z2cg7gupz4jc4z5az53srhxxyvkipqqqpid.onion", 38333),
    ("jnr2iysiyijy7u7uihytbjiq3b254g4i2eaaeod7w7pkrja6ukghx2qd.onion", 38333),
    ("jw6d7rlkcz252f6wv6cirzzrknzuu7xwxnzirab4c5x7wfzl2uzvezad.onion", 38333),
    ("k4d6h4eyeqjn35b3x46f4s3g3eykn4bms52paxuxenkre6nmhfvy6bqd.onion", 38333),
    ("kklfzzodnlinc3toltn7dlft4vzjf2ckmdw2n3dn4lx3pzw5di2womyd.onion", 38333),
    ("kpeo6tc2gix6bxt2bvcsum2g5z5ifgrvt64hatlxztogydyo4tj3pwad.onion", 38333),
    ("lbfzxmkog5ntvcmo7ncsp7ye62onxprf3a42hdzxkjw4inulizd4ccid.onion", 38333),
    ("litqgemqmpesu6gi2ctd4ubrpxdn4mcm2t6p7xhkfxnkk7lzpdx75vyd.onion", 38333),
    ("lkgnafoa5nfd34pzyxpz5gnmpwkbdk5a5h6h7hk3rs53soh6nkb3snqd.onion", 38333),
    ("n6tf5dfz25i4pprczevdkyo5bkpgfa3xigenn6skpjqqynbxpxzilfid.onion", 38333),
    ("nhpn5jnzl64wuhke22bl3avgm7liycl2h2fqh5a5tjtejez6upze4tid.onion", 38333),
    ("o2fumu43ugk6xayo2nvadn7ohqlxharakt4flqh3hjgxdbwzrwignmyd.onion", 38333),
    ("oowqbk36g76cs37sk7myfoq62e7ly42etcfugol3p7haw6ewyn5qhiqd.onion", 38333),
    ("pmjm644pzkp2khwixyis2c7mnfbte33bnmwxdx5lk6t6owvtmapdbhqd.onion", 38333),
    ("qbjhndk6zjpzxfetanqjud3u6kiuspnjfapinw2r5cou6o5ae5mxdzid.onion", 38333),
    ("r4y5pqyvdzq3bzg2fqu46ql4a32fadkftwejtxzckeyohd7wvqnnwtqd.onion", 38333),
    ("tev7cdwka3av6ektydsjfpofmcam3r6qcw7sxbpkohckjvihtzp7hgyd.onion", 38333),
    ("tsq7clffbfe636zfszymheqgy6tyzbsjogad2qet7qeijua5c53ye6ad.onion", 38333),
    ("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion", 38333),
    ("w7d4rwjt5igozi5v7z2m3in2wm3zsf2lhsizqqohkyrokbbie5equoad.onion", 38333),
    ("wevmujl2p6mckcwaxnmtusweros7bu3bxf2g3lzutnfdkjl5gwbu36yd.onion", 38333),
    ("ww4jycomjwnf7jtrrrngeahokqkcl32iufmjzvvk272svieavabjyiqd.onion", 38333),
    ("xbulvl2bb4wvnlafmq3j3fzrjhsmnfz7ubyvl6yy3syeded4tqiubkad.onion", 38333),
    ("xm4kxluodmeolmaugmaxnexnefrg3vsxnqo2ezu7rqmdct7i7xevcxad.onion", 38333),
    ("yjhagyj65xcxu6b5yktu6ntkwsyd5rhjlrsb7sexq5lzchatdqmoqnqd.onion", 38333),
    ("ypi6qgnmabcqlmjfkcnqzpjdjihwmebxkd32tjwt6mrhgm2strfml6ad.onion", 38333),
    ("zgkvv542e4ewviremw3qp4bi52f2sxt4g4mrjrbwonbnfb5oujd44lid.onion", 38333),
];

/// Returns the default P2P port for the given network.
fn default_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Testnet4 => 48333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
    }
}

/// Split a seed entry into `(host, port)`, defaulting the port when the
/// entry doesn't specify one. Handles every form an operator might write
/// for `-signetseednode`:
///
/// - bracketed IPv6 with port: `[2001:db8::1]:38333`
/// - bracketed IPv6, no port:  `[2001:db8::1]`
/// - bare IPv6, no port:       `2001:db8::1`  (RFC 3986 requires brackets
///   to attach a port to an IPv6 literal, so a bare IPv6 never carries one)
/// - IPv4 with/without port:   `192.0.2.7:39333` / `192.0.2.7`
/// - hostname with/without port and `.onion` with/without port
///
/// The bare-IPv6 case is why we can't just `rsplit_once(':')`: that would
/// chop the final hextet of `2001:db8::1` off as a bogus "port".
fn split_seed_host_port(s: &str, default_port: u16) -> (String, u16) {
    let s = s.trim();
    // Bracketed IPv6: `[addr]` or `[addr]:port`.
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = rest[..end].to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return (host, port);
    }
    // Bare IPv6 literal carries no port (must be bracketed to add one).
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return (s.to_string(), default_port);
    }
    // IPv4 or hostname or .onion, with an optional `:port` suffix.
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>().unwrap_or(default_port))
        }
        _ => (s.to_string(), default_port),
    }
}

/// Returns the DNS seed list for the given network.
fn seeds_for_network(network: Network) -> &'static [&'static str] {
    match network {
        Network::Bitcoin => MAINNET_SEEDS,
        Network::Testnet => TESTNET_SEEDS,
        Network::Testnet4 => TESTNET4_SEEDS,
        Network::Signet => SIGNET_SEEDS,
        Network::Regtest => REGTEST_SEEDS,
    }
}

/// Returns hardcoded .onion seed nodes for the given network.
fn onion_seeds_for_network(network: Network) -> &'static [(&'static str, u16)] {
    match network {
        Network::Bitcoin => MAINNET_ONION_SEEDS,
        Network::Testnet => TESTNET_ONION_SEEDS,
        Network::Testnet4 => TESTNET4_ONION_SEEDS,
        Network::Signet => SIGNET_ONION_SEEDS,
        Network::Regtest => &[],
    }
}

/// satd's compiled-in *fixed seeds* (Bitcoin Core's `-fixedseeds`
/// fallback). These are the hardcoded node addresses satd ships — used
/// as a last resort to bootstrap a node with an empty address book and
/// DNS seeding disabled. satd ships well-known `.onion` v3 nodes (which
/// double as the Tor-mode fallback); clearnet fixed-IP seeds are not
/// embedded (they go stale), so on clearnet this list is `.onion`-only
/// and only reachable via a configured proxy.
pub fn fixed_seeds_for_network(network: Network) -> Vec<PeerAddr> {
    onion_seeds_for_network(network)
        .iter()
        .map(|(host, port)| PeerAddr::Onion {
            host: host.to_string(),
            port: *port,
        })
        .collect()
}

/// The seeds a node under `-proxy` reaches by name, as `addr-fetch`
/// connections the proxy resolves: each of the network's DNS seeds, and on
/// signet each `-signetseednode` entry that needs a lookup, at the
/// network's default port unless the entry names one. Core does the same
/// when a name proxy is set (`ThreadDNSAddressSeed`: `AddAddrFetch(seed)`
/// when `HaveNameProxy()`, rather than `LookupHost`), so a proxied node
/// whose `-onlynet` leaves out onion still bootstraps, and nothing is looked
/// up on the local resolver.
pub fn proxied_seed_names(network: Network, extra_signet_seeds: &[String]) -> Vec<(String, u16)> {
    let port = default_port(network);
    let mut out: Vec<(String, u16)> = seeds_for_network(network)
        .iter()
        .map(|seed| split_seed_host_port(seed, port))
        .collect();
    if network == Network::Signet {
        out.extend(operator_seed_names(extra_signet_seeds, network));
    }
    out
}

/// The entries of an operator seed list (`-seednode`, `-signetseednode`)
/// that are host names: neither an IP literal nor a `.onion` address. Under
/// `-proxy` these are reached by name, as `addr-fetch` connections the proxy
/// resolves (Core's `AddAddrFetch` with a name proxy); without one
/// [`resolve_operator_seeds`] looks them up.
pub fn operator_seed_names(seeds: &[String], network: Network) -> Vec<(String, u16)> {
    let port = default_port(network);
    seeds
        .iter()
        .map(|seed| split_seed_host_port(seed, port))
        .filter(|(host, _)| !host.ends_with(".onion") && host.parse::<std::net::IpAddr>().is_err())
        .collect()
}

/// Resolve seeds for the given network, returning PeerAddr values.
///
/// When a proxy is configured, uses hardcoded .onion seeds instead of
/// clearnet DNS to avoid DNS leaks through the local network.
pub async fn resolve_seeds(network: Network, proxy: Option<&str>) -> Vec<PeerAddr> {
    resolve_seeds_with(network, proxy, &[]).await
}

/// Resolve DNS / .onion seeds, prepending any operator-supplied
/// signet seed nodes (Bitcoin Core's `-signetseednode=<host[:port]>`,
/// repeatable). Extra seeds are honoured only on Signet — passing
/// them on other networks has no effect, matching Core's semantics.
/// The extras come BEFORE the built-in seeds so a private-signet
/// operator's nodes get tried first; the built-ins remain as
/// fallback in case the private seeds are down.
/// Resolve operator-supplied seed strings (Bitcoin Core's `-seednode` /
/// `-signetseednode`, format `host[:port]`) into `PeerAddr`s, supplying
/// the network default P2P port when the port is omitted. Handles:
///
/// - `.onion[:port]` — kept as an onion target (proxy-routed; safe in
///   any mode);
/// - literal IPv4 / `[IPv6]` — used directly (default port if omitted),
///   no name resolution so nothing to leak;
/// - DNS hostnames — resolved locally, EXCEPT under proxy mode where the
///   lookup is skipped to avoid leaking it to the local resolver
///   (`PeerAddr` has no clearnet-hostname variant to hand to the proxy
///   for remote resolution; use a `.onion` or literal IP there instead).
///
/// Entries that fail to resolve are logged and dropped — never fatal.
/// Resolve an `-addnode` / `-connect` / `addnode`-RPC target into something
/// dialable, honouring `-proxy` and `-dns`.
///
/// This is the single entry point for operator-supplied peer targets.
/// `PeerAddr::parse_with_default_port` stays the pure parser; everything
/// that can touch the network goes through here, because the parser was
/// doing three things it must not:
///
/// * it resolved hostnames with the **blocking** `std::net::ToSocketAddrs`,
///   from inside async handlers — a slow or unreachable resolver parked a
///   tokio worker for the whole DNS timeout;
/// * it resolved them with the **local** resolver even under `-proxy`,
///   which leaks to the network operator exactly the peer names a proxied
///   node exists to hide (the same leak `resolve_operator_seeds` already
///   refuses for `-seednode`);
/// * it ignored `-dns=0` entirely, so a node told not to do name lookups
///   did them anyway.
///
/// `.onion` targets and literal IPs never reach a resolver and so are
/// accepted in every mode.
pub async fn resolve_peer_target(
    s: &str,
    default_port: u16,
    proxy: Option<&str>,
    dns: bool,
) -> Result<PeerAddr, String> {
    resolve_peer_target_classified(s, default_port, proxy, dns)
        .await
        .map_err(|e| e.to_string())
}

/// Why an operator-supplied peer target did not become an address.
///
/// The two cases call for different handling. A target that is refused can
/// never resolve under this configuration, so keeping it around to retry
/// would only repeat the same error. A name whose lookup failed may well
/// resolve later: a peer brought up alongside this node (as container
/// orchestrators do) often has no DNS record for the first few seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTargetError {
    /// Malformed, or a name this node is configured never to look up
    /// (`-dns=0`, or `-proxy`, under which a local lookup would leak).
    Refused(String),
    /// A permitted name lookup failed. Retrying may succeed.
    Lookup(String),
}

impl std::fmt::Display for PeerTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerTargetError::Refused(m) | PeerTargetError::Lookup(m) => f.write_str(m),
        }
    }
}

/// [`resolve_peer_target`], keeping apart a refusal from a failed lookup.
pub async fn resolve_peer_target_classified(
    s: &str,
    default_port: u16,
    proxy: Option<&str>,
    dns: bool,
) -> Result<PeerAddr, PeerTargetError> {
    if let Some(addr) = classify_peer_target(s, default_port, proxy, dns)? {
        return Ok(addr);
    }
    let (host, port) = split_seed_host_port(s, default_port);
    match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(mut it) => it.next().map(PeerAddr::Socket).ok_or_else(|| {
            PeerTargetError::Lookup(format!("invalid address '{s}': could not resolve"))
        }),
        Err(e) => Err(PeerTargetError::Lookup(format!(
            "invalid address '{s}': could not resolve: {e}"
        ))),
    }
}

/// The part of [`resolve_peer_target_classified`] that needs no lookup:
/// the address of a `.onion` or IP-literal target, `None` for a host name
/// that has to be looked up, or the refusal of a target that can never
/// resolve here (malformed, `-dns=0`, `-proxy`).
///
/// Never waits on a resolver, so startup can register the operator's
/// targets before it serves RPC and look the names up afterwards.
pub fn classify_peer_target(
    s: &str,
    default_port: u16,
    proxy: Option<&str>,
    dns: bool,
) -> Result<Option<PeerAddr>, PeerTargetError> {
    // `.onion` and literal-IP forms: no lookup, no leak, always allowed.
    // (`parse_with_default_port` handles these without touching the
    // resolver; `is_name_target` decides which forms those are.)
    if !is_name_target(s) {
        return PeerAddr::parse_with_default_port(s, default_port)
            .map(Some)
            .map_err(PeerTargetError::Refused);
    }
    let (host, _) = split_seed_host_port(s, default_port);
    if !dns {
        return Err(PeerTargetError::Refused(format!(
            "cannot resolve '{host}': DNS lookups are disabled (-dns=0); \
             use a literal IP address or a .onion address"
        )));
    }
    if proxy.is_some() {
        return Err(PeerTargetError::Refused(format!(
            "refusing to resolve '{host}' locally under -proxy (it would leak \
             the lookup to your resolver); use a literal IP address or a \
             .onion address"
        )));
    }
    Ok(None)
}

/// Whether `s` names a `.onion` service, with or without a port.
///
/// Decided by inspection, never by a resolver, so a caller can refuse or
/// route an onion target synchronously.
pub fn is_onion_target(s: &str) -> bool {
    if s.ends_with(".onion") {
        return true;
    }
    matches!(s.rsplit_once(':'), Some((host, _)) if host.ends_with(".onion"))
}

/// Whether `s` needs a name lookup to become a socket address — i.e. it is
/// neither a `.onion` target nor an IP literal (with or without a port).
pub fn is_name_target(s: &str) -> bool {
    if is_onion_target(s) {
        return false;
    }
    if s.parse::<SocketAddr>().is_ok() || s.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // `[2001:db8::1]:8333` parses as a SocketAddr above; a bracketed literal
    // without a port does not, so check it explicitly rather than sending it
    // to a resolver.
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_err();
    }
    true
}

pub async fn resolve_operator_seeds(
    seeds: &[String],
    network: Network,
    proxy: Option<&str>,
) -> Vec<PeerAddr> {
    let port = default_port(network);
    let mut out: Vec<PeerAddr> = Vec::new();
    for seed in seeds {
        let (host, p) = split_seed_host_port(seed, port);
        if host.ends_with(".onion") {
            out.push(PeerAddr::Onion { host, port: p });
        } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            out.push(PeerAddr::Socket(SocketAddr::new(ip, p)));
        } else if proxy.is_some() {
            // Not looked up here, which would leak the query: under a proxy
            // the caller opens it by name (`operator_seed_names`).
            tracing::debug!(seed = %host, "seed node host name left for the proxy to resolve");
        } else {
            let target = format!("{host}:{p}");
            match tokio::net::lookup_host(&target).await {
                Ok(resolved) => out.extend(resolved.map(PeerAddr::Socket)),
                Err(e) => tracing::warn!(seed = %host, "seed node lookup failed: {}", e),
            }
        }
    }
    out
}

pub async fn resolve_seeds_with(
    network: Network,
    proxy: Option<&str>,
    extra_signet_seeds: &[String],
) -> Vec<PeerAddr> {
    let mut prepend: Vec<PeerAddr> = Vec::new();
    if network == Network::Signet {
        prepend = resolve_operator_seeds(extra_signet_seeds, network, proxy).await;
        if !prepend.is_empty() {
            tracing::info!(
                count = prepend.len(),
                "operator-supplied signet seed nodes resolved"
            );
        }
    }

    let builtins: Vec<PeerAddr> = if proxy.is_some() {
        // Tor mode: use hardcoded .onion seeds to avoid DNS leaks
        let onion_seeds = onion_seeds_for_network(network);
        if onion_seeds.is_empty() {
            tracing::debug!("No .onion seeds configured for network {}", network);
            Vec::new()
        } else {
            tracing::info!(
                count = onion_seeds.len(),
                "Using .onion seed nodes (proxy mode, no DNS leak)"
            );
            onion_seeds
                .iter()
                .map(|(host, port)| PeerAddr::Onion {
                    host: host.to_string(),
                    port: *port,
                })
                .collect()
        }
    } else {
        // Clearnet: normal DNS resolution
        resolve_dns_seeds(network)
            .await
            .into_iter()
            .map(PeerAddr::Socket)
            .collect()
    };

    prepend.extend(builtins);
    prepend
}

/// Resolve DNS seeds for the given network, returning a list of socket
/// addresses (IP + default P2P port). Returns an empty vec if all lookups
/// fail or no seeds are configured (e.g. regtest).
pub async fn resolve_dns_seeds(network: Network) -> Vec<SocketAddr> {
    let seeds = seeds_for_network(network);
    let port = default_port(network);

    if seeds.is_empty() {
        tracing::debug!("No DNS seeds configured for network {}", network);
        return Vec::new();
    }

    let mut addrs = Vec::new();

    for seed in seeds {
        let host = format!("{}:{}", seed, port);
        match tokio::net::lookup_host(&host).await {
            Ok(resolved) => {
                let before = addrs.len();
                addrs.extend(resolved);
                let found = addrs.len() - before;
                tracing::debug!(seed, found, "DNS seed resolved");
            }
            Err(e) => {
                tracing::warn!(seed, "DNS seed lookup failed: {}", e);
            }
        }
    }

    tracing::info!(
        count = addrs.len(),
        seeds = seeds.len(),
        "DNS seed resolution complete"
    );

    addrs
}

#[cfg(test)]
mod tests {

    /// A refusal can never succeed under this configuration and is not
    /// retried; a failed lookup can, and is. Callers keep the two apart.
    #[tokio::test]
    async fn refusals_and_failed_lookups_are_told_apart() {
        use super::PeerTargetError::{Lookup, Refused};
        let dns_off = resolve_peer_target_classified("tank-0000:18444", 18444, None, false).await;
        assert!(matches!(dns_off, Err(Refused(_))), "{dns_off:?}");
        let proxied = resolve_peer_target_classified("tank-0000", 18444, Some("127.0.0.1:9050"), true).await;
        assert!(matches!(proxied, Err(Refused(_))), "{proxied:?}");
        let missing = resolve_peer_target_classified("tank-0000.invalid", 18444, None, true).await;
        assert!(matches!(missing, Err(Lookup(_))), "{missing:?}");
    }

    use super::*;

    #[test]
    fn test_seeds_for_network() {
        // Counts track Bitcoin Core v28.0 `vSeeds` per network. Mainnet keeps
        // one extra (`seed.bitcoinstats.com`) that Core has since dropped, so
        // it is Core's 9 + 1.
        assert_eq!(seeds_for_network(Network::Bitcoin).len(), 10);
        assert_eq!(seeds_for_network(Network::Testnet).len(), 5);
        assert_eq!(seeds_for_network(Network::Testnet4).len(), 2);
        // Two DNS seeds + Core's default-signet clearnet literal.
        assert_eq!(seeds_for_network(Network::Signet).len(), 3);
        assert!(seeds_for_network(Network::Regtest).is_empty());
    }

    #[test]
    fn test_core_parity_seeds_present() {
        // Golden membership checks: the seeds Core v28.0 added that satd was
        // previously missing must be present, so a future edit can't silently
        // drop Core parity.
        let mainnet = seeds_for_network(Network::Bitcoin);
        assert!(mainnet.contains(&"seed.bitcoin.wiz.biz"));
        assert!(mainnet.contains(&"seed.mainnet.achownodes.xyz"));

        let testnet = seeds_for_network(Network::Testnet);
        assert!(testnet.contains(&"seed.testnet.bitcoin.sprovoost.nl"));
        assert!(testnet.contains(&"seed.testnet.achownodes.xyz"));

        let signet = seeds_for_network(Network::Signet);
        assert!(signet.contains(&"seed.signet.achownodes.xyz"));
        // Core's default-signet clearnet seed (a literal IP in vSeeds).
        assert!(signet.contains(&"178.128.221.177"));

        // Core seeds the default signet with this Tor v3 node.
        assert!(
            onion_seeds_for_network(Network::Signet)
                .iter()
                .any(|(h, p)| *h
                    == "v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion"
                    && *p == 38333)
        );
    }

    #[tokio::test]
    async fn signet_clearnet_literal_resolves_without_dns() {
        // The default-signet clearnet seed is a numeric literal, so the same
        // `lookup_host("{seed}:{port}")` path the seeder uses returns it
        // directly with no DNS query — proving it's a usable bootstrap target.
        let port = default_port(Network::Signet);
        let literal = seeds_for_network(Network::Signet)
            .iter()
            .find(|s| s.parse::<std::net::IpAddr>().is_ok())
            .expect("signet should carry a clearnet literal seed");
        let resolved: Vec<_> = tokio::net::lookup_host(format!("{literal}:{port}"))
            .await
            .expect("numeric literal resolves offline")
            .collect();
        assert_eq!(resolved, vec!["178.128.221.177:38333".parse().unwrap()]);
    }

    #[test]
    fn test_default_port() {
        assert_eq!(default_port(Network::Bitcoin), 8333);
        assert_eq!(default_port(Network::Testnet), 18333);
        assert_eq!(default_port(Network::Signet), 38333);
        assert_eq!(default_port(Network::Regtest), 18444);
    }

    #[test]
    fn test_onion_seeds_mainnet() {
        let seeds = onion_seeds_for_network(Network::Bitcoin);
        assert!(!seeds.is_empty());
        for (host, port) in seeds {
            assert!(host.ends_with(".onion"));
            assert_eq!(*port, 8333);
        }
    }

    /// Every public network has `.onion` seeds, each a well-formed Tor v3
    /// address (56 base32 characters) on the network's default port, with no
    /// duplicates, so a Tor-only node can bootstrap on any of them (#1162).
    #[test]
    fn every_public_network_has_well_formed_onion_seeds() {
        for (network, at_least) in [
            (Network::Bitcoin, 100),
            (Network::Testnet, 20),
            (Network::Testnet4, 20),
            (Network::Signet, 20),
        ] {
            let seeds = onion_seeds_for_network(network);
            assert!(seeds.len() >= at_least, "{network}: only {} onion seeds", seeds.len());
            let mut seen = std::collections::HashSet::new();
            for (host, port) in seeds {
                let label = host.strip_suffix(".onion").unwrap_or_else(|| panic!("{network}: {host} is not .onion"));
                assert!(
                    label.len() == 56 && label.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
                    "{network}: {host} is not a Tor v3 address"
                );
                assert_eq!(*port, default_port(network), "{network}: {host}");
                assert!(seen.insert(*host), "{network}: {host} listed twice");
            }
        }
    }

    #[test]
    fn test_onion_seeds_regtest_empty() {
        assert!(onion_seeds_for_network(Network::Regtest).is_empty());
    }

    #[tokio::test]
    async fn test_resolve_seeds_proxy_returns_onion() {
        let addrs = resolve_seeds(Network::Bitcoin, Some("127.0.0.1:9050")).await;
        assert!(!addrs.is_empty());
        for addr in &addrs {
            assert!(addr.is_onion());
        }
    }

    #[tokio::test]
    async fn extra_signet_seeds_ignored_off_signet() {
        // Bitcoin Core's -signetseednode is signet-only. On other
        // networks the extras must be ignored so an operator with a
        // single multi-section config can leave `signetseednode=` in
        // the `[signet]` block without contaminating mainnet runs.
        let extras = vec!["192.0.2.5:38333".to_string()];
        let addrs = resolve_seeds_with(Network::Regtest, None, &extras).await;
        // Regtest has no built-in seeds, so this should be empty.
        assert!(addrs.is_empty(), "regtest seeds should be empty");
    }

    #[tokio::test]
    async fn extra_signet_seeds_literal_ipv4_prepends() {
        // Literal IP — bypasses DNS, parsed directly. We add a TEST-NET-3
        // (RFC 5737) address that's guaranteed unroutable so this test
        // doesn't accidentally rely on the network.
        let extras = vec!["192.0.2.7:39333".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, None, &extras).await;
        assert!(!addrs.is_empty());
        match &addrs[0] {
            PeerAddr::Socket(sa) => {
                assert_eq!(sa.to_string(), "192.0.2.7:39333");
            }
            _ => panic!("expected first seed to be the operator-supplied literal IP"),
        }
    }

    #[tokio::test]
    async fn extra_signet_seeds_default_port_when_missing() {
        // Bare host (no `:port`) inherits signet's default P2P port.
        let extras = vec!["192.0.2.42".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, None, &extras).await;
        match &addrs[0] {
            PeerAddr::Socket(sa) => {
                assert_eq!(sa.port(), 38333);
            }
            _ => panic!("expected literal IP entry"),
        }
    }

    // ---- H2: operator -seednode resolution (host[:port], default port,
    //      onion, proxy-leak guard). Uses RFC 5737 addrs / no live DNS. ----

    #[tokio::test]
    async fn operator_seed_literal_ip_gets_default_port() {
        // The review's `1.2.3.4`-style case: a port-less literal IP must
        // resolve to the network default port, not silently no-op.
        let out =
            resolve_operator_seeds(&["192.0.2.7".to_string()], Network::Bitcoin, None).await;
        assert_eq!(out.len(), 1);
        match &out[0] {
            PeerAddr::Socket(sa) => assert_eq!(sa.port(), default_port(Network::Bitcoin)),
            _ => panic!("expected a socket addr with the default port"),
        }
    }

    #[tokio::test]
    async fn operator_seed_ip_with_port_is_preserved() {
        let out =
            resolve_operator_seeds(&["192.0.2.7:8333".to_string()], Network::Bitcoin, None).await;
        match &out[0] {
            PeerAddr::Socket(sa) => assert_eq!(sa.port(), 8333),
            _ => panic!("expected socket addr"),
        }
    }

    #[tokio::test]
    async fn operator_seed_onion_preserved_under_proxy() {
        let out = resolve_operator_seeds(
            &["abcdefghij234567.onion:8333".to_string()],
            Network::Bitcoin,
            Some("127.0.0.1:9050"),
        )
        .await;
        match &out[0] {
            PeerAddr::Onion { port, .. } => assert_eq!(*port, 8333),
            _ => panic!("expected onion addr"),
        }
    }

    #[tokio::test]
    async fn operator_seed_hostname_skipped_under_proxy() {
        // DNS-leak guard: a clearnet hostname under proxy mode is dropped
        // (no local lookup), rather than leaking the query.
        let out = resolve_operator_seeds(
            &["seed.example.com".to_string()],
            Network::Bitcoin,
            Some("127.0.0.1:9050"),
        )
        .await;
        assert!(out.is_empty());
    }

    /// #994: what a proxied node reaches by name. Every DNS seed at the
    /// network's port, the signet operator seeds that need a lookup, and
    /// nothing that is an IP literal or an onion address (those are dialled
    /// as they are). Perturbation: drop the IP-literal filter in
    /// `operator_seed_names` and `192.0.2.7` is listed.
    #[test]
    fn a_proxied_node_reaches_dns_seeds_and_seed_hostnames_by_name() {
        let names = proxied_seed_names(Network::Bitcoin, &[]);
        assert_eq!(names.len(), MAINNET_SEEDS.len());
        assert!(names.iter().all(|(h, p)| *p == 8333 && MAINNET_SEEDS.contains(&h.as_str())));
        assert!(proxied_seed_names(Network::Regtest, &[]).is_empty());

        let ops = vec![
            "seed.example.com".to_string(),
            "seed2.example.com:39333".to_string(),
            "192.0.2.7".to_string(),
            "[2001:db8::1]:38333".to_string(),
            "6megrst422lxzsqvshkqkg6z2zl2f6n532vy7t5hj5xmfoauoygzqad.onion".to_string(),
        ];
        let expected = vec![
            ("seed.example.com".to_string(), 38333),
            ("seed2.example.com".to_string(), 39333),
        ];
        assert_eq!(operator_seed_names(&ops, Network::Signet), expected);
        let signet = proxied_seed_names(Network::Signet, &ops);
        assert!(signet.ends_with(&expected), "{signet:?}");
        // The extras are signet's only.
        assert_eq!(proxied_seed_names(Network::Bitcoin, &ops).len(), MAINNET_SEEDS.len());
    }

    #[test]
    fn split_seed_host_port_forms() {
        // Bracketed IPv6 with and without port.
        assert_eq!(
            split_seed_host_port("[2001:db8::1]:38333", 38333),
            ("2001:db8::1".to_string(), 38333)
        );
        assert_eq!(
            split_seed_host_port("[2001:db8::1]", 38333),
            ("2001:db8::1".to_string(), 38333)
        );
        assert_eq!(
            split_seed_host_port("[2001:db8::1]:39000", 38333),
            ("2001:db8::1".to_string(), 39000)
        );
        // Bare IPv6 never carries a port — the trailing `::1` must not be
        // mistaken for `:1`.
        assert_eq!(
            split_seed_host_port("2001:db8::1", 38333),
            ("2001:db8::1".to_string(), 38333)
        );
        assert_eq!(
            split_seed_host_port("::1", 38333),
            ("::1".to_string(), 38333)
        );
        // IPv4 and hostnames, with and without port.
        assert_eq!(
            split_seed_host_port("192.0.2.7:39333", 38333),
            ("192.0.2.7".to_string(), 39333)
        );
        assert_eq!(
            split_seed_host_port("192.0.2.7", 38333),
            ("192.0.2.7".to_string(), 38333)
        );
        assert_eq!(
            split_seed_host_port("seed.example.com:38333", 38333),
            ("seed.example.com".to_string(), 38333)
        );
        assert_eq!(
            split_seed_host_port("abcd.onion", 38333),
            ("abcd.onion".to_string(), 38333)
        );
    }

    #[tokio::test]
    async fn extra_signet_seeds_bracketed_ipv6_prepends() {
        let extras = vec!["[2001:db8::1]:39333".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, None, &extras).await;
        match &addrs[0] {
            PeerAddr::Socket(sa) => {
                assert!(sa.is_ipv6());
                assert_eq!(sa.to_string(), "[2001:db8::1]:39333");
            }
            _ => panic!("expected bracketed IPv6 to parse as a Socket"),
        }
    }

    #[tokio::test]
    async fn extra_signet_seeds_bare_ipv6_default_port() {
        let extras = vec!["2001:db8::5".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, None, &extras).await;
        match &addrs[0] {
            PeerAddr::Socket(sa) => {
                assert!(sa.is_ipv6());
                assert_eq!(sa.port(), 38333);
            }
            _ => panic!("expected bare IPv6 to parse as a Socket with default port"),
        }
    }

    #[tokio::test]
    async fn extra_signet_dns_seed_skipped_under_proxy() {
        // A DNS-name signet seed must NOT be resolved locally when a
        // proxy is configured — that would leak the lookup. The entry is
        // dropped, so only the built-in .onion seeds remain and nothing
        // in the result is a clearnet Socket.
        let extras = vec!["seed.example.invalid".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, Some("127.0.0.1:9050"), &extras).await;
        assert!(
            addrs.iter().all(|a| a.is_onion()),
            "DNS seed must be skipped under proxy; got a non-onion entry: {addrs:?}",
        );
    }

    #[tokio::test]
    async fn extra_signet_seeds_onion_routes_as_onion() {
        // A `.onion` host stays an Onion variant so the proxy routes
        // it correctly. The proxy is set so the built-in onion seeds
        // also come through.
        let extras = vec!["abcd1234.onion:38333".to_string()];
        let addrs = resolve_seeds_with(Network::Signet, Some("127.0.0.1:9050"), &extras).await;
        match &addrs[0] {
            PeerAddr::Onion { host, port } => {
                assert_eq!(host, "abcd1234.onion");
                assert_eq!(*port, 38333);
            }
            _ => panic!("expected first seed to be an Onion variant"),
        }
    }

    /// `-dns=0` means "do not do name lookups". It was parsed and then only
    /// consulted for DNS *seeding*, so `-addnode=example.com` resolved
    /// anyway — the one thing the flag exists to prevent.
    #[tokio::test]
    async fn dns_disabled_refuses_a_hostname_but_not_a_literal() {
        let err = resolve_peer_target("example.invalid:8333", 8333, None, false)
            .await
            .expect_err("a hostname needs a lookup");
        assert!(err.contains("-dns=0"), "{err}");

        // Literals and onion targets never touch a resolver, so they are
        // still accepted.
        assert_eq!(
            resolve_peer_target("1.2.3.4", 8333, None, false).await.unwrap(),
            PeerAddr::Socket("1.2.3.4:8333".parse().unwrap())
        );
        assert_eq!(
            resolve_peer_target("[2001:db8::1]:1234", 8333, None, false).await.unwrap(),
            PeerAddr::Socket("[2001:db8::1]:1234".parse().unwrap())
        );
        let onion = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion:8333";
        assert!(matches!(
            resolve_peer_target(onion, 8333, None, false).await.unwrap(),
            PeerAddr::Onion { .. }
        ));
    }

    /// Resolving a peer hostname with the *local* resolver while `-proxy` is
    /// set hands the operator's network exactly the peer names the proxy
    /// exists to hide. `resolve_operator_seeds` already refuses this for
    /// `-seednode`; the addnode/connect path did it anyway.
    #[tokio::test]
    async fn a_hostname_is_not_resolved_locally_under_a_proxy() {
        let err = resolve_peer_target("example.invalid:8333", 8333, Some("127.0.0.1:9050"), true)
            .await
            .expect_err("a proxied node must not leak the lookup");
        assert!(err.contains("-proxy"), "{err}");

        // A .onion target under the same proxy is the supported form and is
        // handed on untouched, for the proxy itself to resolve.
        let onion = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion:8333";
        assert!(matches!(
            resolve_peer_target(onion, 8333, Some("127.0.0.1:9050"), true).await.unwrap(),
            PeerAddr::Onion { .. }
        ));
        // As is a literal IP.
        assert_eq!(
            resolve_peer_target("1.2.3.4:1234", 8333, Some("127.0.0.1:9050"), true).await.unwrap(),
            PeerAddr::Socket("1.2.3.4:1234".parse().unwrap())
        );
    }

    /// A name still resolves when nothing forbids it — and `localhost` is
    /// the one name guaranteed present on any machine running the suite.
    #[tokio::test]
    async fn a_hostname_still_resolves_with_no_proxy_and_dns_on() {
        let addr = resolve_peer_target("localhost:18444", 8333, None, true)
            .await
            .expect("localhost resolves");
        match addr {
            PeerAddr::Socket(sa) => {
                assert!(sa.ip().is_loopback(), "{sa}");
                assert_eq!(sa.port(), 18444);
            }
            other => panic!("expected a socket, got {other}"),
        }
        // No port given: the network default is applied.
        let addr = resolve_peer_target("localhost", 18444, None, true).await.unwrap();
        assert_eq!(addr.port(), 18444);
    }

    /// The classifier decides which inputs may reach a resolver at all, so
    /// every literal form has to be recognised as *not* a name — otherwise a
    /// `-proxy` node would refuse to dial a bare IP.
    #[test]
    fn only_real_names_are_classified_as_needing_a_lookup() {
        for literal in [
            "1.2.3.4",
            "1.2.3.4:8333",
            "2001:db8::1",
            "[2001:db8::1]",
            "[2001:db8::1]:8333",
            "::1",
            "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion",
            "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion:8333",
        ] {
            assert!(!is_name_target(literal), "{literal} is a literal");
        }
        for name in ["example.com", "example.com:8333", "localhost", "127.1:8333"] {
            assert!(is_name_target(name), "{name} needs a lookup");
        }
    }

    /// Startup registers each `-addnode` entry with `classify_peer_target`
    /// before it serves RPC (#876), so the classifier has to reach the
    /// resolver's verdict on everything the resolver decides without a
    /// lookup, and leave only a permitted name for the lookup. (That it
    /// never looks anything up is the compiler's to check: it is not async.)
    #[tokio::test]
    async fn classifying_a_target_agrees_with_resolving_it_short_of_the_lookup() {
        let onion = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion";
        let proxy = Some("127.0.0.1:9050");
        for (target, proxy, dns) in [
            ("1.2.3.4".to_string(), None, true),
            ("1.2.3.4:1234".to_string(), proxy, false),
            ("[2001:db8::1]:1234".to_string(), None, false),
            (format!("{onion}:8333"), proxy, true),
            (format!("{onion}:notaport"), None, true),
            ("example.invalid:8333".to_string(), None, false),
            ("example.invalid:8333".to_string(), proxy, true),
        ] {
            let resolved = resolve_peer_target_classified(&target, 8333, proxy, dns).await;
            assert_eq!(
                classify_peer_target(&target, 8333, proxy, dns),
                resolved.map(Some),
                "{target} (proxy {proxy:?}, dns {dns})"
            );
        }
        for name in ["example.invalid:8333", "localhost"] {
            assert_eq!(classify_peer_target(name, 8333, None, true), Ok(None), "{name}");
        }
    }
}
