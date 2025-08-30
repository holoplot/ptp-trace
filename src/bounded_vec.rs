use std::collections::VecDeque;

/// A deque that maintains a maximum capacity by removing oldest elements
#[derive(Debug, Clone)]
pub struct BoundedVec<T> {
    pub items: VecDeque<T>,
    pub max_size: usize,
}

impl<T> BoundedVec<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            items: VecDeque::new(),
            max_size,
        }
    }

    pub fn push(&mut self, item: T) {
        self.items.push_back(item);
        if self.items.len() > self.max_size {
            self.items.pop_front();
        }
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}
