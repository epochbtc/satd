/// Optimized IF/ELSE/ENDIF condition stack.
///
/// Tracks nested conditional execution state without materializing a vector
/// of booleans. Only stores the stack size and position of the first false
/// value. This matches Bitcoin Core's `ConditionStack` exactly.
pub struct ConditionStack {
    /// The size of the implied stack.
    stack_size: u32,
    /// The position of the first false value, or NO_FALSE if all true.
    first_false_pos: u32,
}

const NO_FALSE: u32 = u32::MAX;

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionStack {
    pub fn new() -> Self {
        Self {
            stack_size: 0,
            first_false_pos: NO_FALSE,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stack_size == 0
    }

    /// Returns true if all values on the stack are true (i.e., we are in an
    /// active execution branch).
    pub fn all_true(&self) -> bool {
        self.first_false_pos == NO_FALSE
    }

    pub fn push_back(&mut self, value: bool) {
        if self.first_false_pos == NO_FALSE && !value {
            self.first_false_pos = self.stack_size;
        }
        self.stack_size += 1;
    }

    pub fn pop_back(&mut self) {
        assert!(self.stack_size > 0);
        self.stack_size -= 1;
        if self.first_false_pos == self.stack_size {
            self.first_false_pos = NO_FALSE;
        }
    }

    pub fn toggle_top(&mut self) {
        assert!(self.stack_size > 0);
        if self.first_false_pos == NO_FALSE {
            // All true; top becomes the first false.
            self.first_false_pos = self.stack_size - 1;
        } else if self.first_false_pos == self.stack_size - 1 {
            // Top is the first false; toggling makes everything true.
            self.first_false_pos = NO_FALSE;
        }
        // Otherwise, there is a false value below the top; toggling the top
        // is unobservable.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let mut cs = ConditionStack::new();
        assert!(cs.is_empty());
        assert!(cs.all_true());

        cs.push_back(true);
        assert!(!cs.is_empty());
        assert!(cs.all_true());

        cs.push_back(false);
        assert!(!cs.all_true());

        cs.pop_back();
        assert!(cs.all_true());

        cs.pop_back();
        assert!(cs.is_empty());
    }

    #[test]
    fn test_toggle() {
        let mut cs = ConditionStack::new();
        cs.push_back(true);
        assert!(cs.all_true());

        cs.toggle_top(); // true -> false
        assert!(!cs.all_true());

        cs.toggle_top(); // false -> true
        assert!(cs.all_true());
    }

    #[test]
    fn test_nested_false() {
        let mut cs = ConditionStack::new();
        cs.push_back(true);
        cs.push_back(false);
        cs.push_back(true); // doesn't matter, first false is at position 1
        assert!(!cs.all_true());

        cs.pop_back(); // remove top true
        assert!(!cs.all_true());

        cs.pop_back(); // remove the false
        assert!(cs.all_true());
    }
}
