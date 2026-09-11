/// Scroll offsets and measured content for one pane, in terminal cells.
/// Rendering supplies measurements; input handling only changes offsets.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Viewport {
    pub(super) x: u16,
    pub(super) y: u16,
    pub(super) rows: usize,
    pub(super) columns: usize,
    pub(super) height: usize,
    pub(super) width: usize,
}

impl Viewport {
    pub(super) fn update(
        &mut self,
        rows: usize,
        columns: usize,
        height: usize,
        width: usize,
        wrap: bool,
        follow: bool,
    ) {
        self.rows = rows;
        self.columns = columns;
        self.height = height;
        self.width = width;
        self.y = if follow {
            self.max_y()
        } else {
            self.y.min(self.max_y())
        };
        self.x = if wrap { 0 } else { self.x.min(self.max_x()) };
    }

    pub(super) fn max_y(&self) -> u16 {
        scroll_limit(self.rows, self.height)
    }

    pub(super) fn max_x(&self) -> u16 {
        scroll_limit(self.columns, self.width)
    }

    pub(super) fn scroll_y(&mut self, delta: i32) {
        self.y = (i64::from(self.y) + i64::from(delta)).clamp(0, i64::from(self.max_y())) as u16;
    }

    pub(super) fn scroll_x(&mut self, delta: i32) {
        self.x = (i64::from(self.x) + i64::from(delta)).clamp(0, i64::from(self.max_x())) as u16;
    }

    pub(super) fn follow_bottom(&mut self) {
        self.y = self.max_y();
    }

    pub(super) fn offset(&self) -> (u16, u16) {
        (self.y, self.x)
    }

    pub(super) fn indicators(&self, wrap: bool) -> String {
        let mut arrows = String::new();
        if self.y > 0 {
            arrows.push('↑');
        }
        if usize::from(self.y) + self.height.max(1) < self.rows {
            arrows.push('↓');
        }
        if !wrap {
            if self.x > 0 {
                arrows.push('←');
            }
            if usize::from(self.x) + self.width.max(1) < self.columns {
                arrows.push('→');
            }
        }
        if arrows.is_empty() {
            arrows
        } else {
            format!(" {arrows} ")
        }
    }
}

fn scroll_limit(content: usize, visible: usize) -> u16 {
    content
        .saturating_sub(visible.max(1))
        .min(usize::from(u16::MAX)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_and_wrap_clamp_existing_offsets() {
        let mut view = Viewport::default();
        view.update(100, 100, 10, 20, false, false);
        view.scroll_y(80);
        view.scroll_x(70);
        view.update(100, 100, 90, 80, false, false);
        assert_eq!(view.offset(), (10, 20));
        view.update(100, 100, 90, 80, true, false);
        assert_eq!(view.offset(), (10, 0));
    }

    #[test]
    fn follow_only_scrolls_overflowing_content() {
        let mut view = Viewport::default();
        for (rows, expected) in [(3, 0), (20, 0), (25, 5)] {
            view.update(rows, 0, 20, 10, true, true);
            assert_eq!(view.y, expected);
        }
    }

    #[test]
    fn offsets_saturate_instead_of_wrapping_for_large_content() {
        let mut view = Viewport::default();
        view.update(100_000, 100_000, 0, 0, false, true);
        view.scroll_x(i32::MAX);
        assert_eq!(view.offset(), (u16::MAX, u16::MAX));
        view.scroll_y(i32::MIN);
        view.scroll_x(i32::MIN);
        assert_eq!(view.offset(), (0, 0));
    }

    #[test]
    fn indicators_match_available_directions() {
        let mut view = Viewport::default();
        view.update(10, 40, 3, 10, false, false);
        assert_eq!(view.indicators(false), " ↓→ ");
        view.scroll_y(2);
        view.scroll_x(5);
        assert_eq!(view.indicators(false), " ↑↓←→ ");
        assert_eq!(view.indicators(true), " ↑↓ ");
    }
}
