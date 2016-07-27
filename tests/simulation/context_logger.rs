use env_logger;
use env_logger::fmt::Color;
use futures::{Future, Poll};
use std::cell::RefCell;
use std::io::Write;
use std::sync::{Once, ONCE_INIT};

thread_local! {
    pub static LOG_CONTEXT: RefCell<Option<usize>> = RefCell::new(None);
}

static INIT: Once = ONCE_INIT;
static COLORS: &[Color] = &[
    Color::Red,
    Color::Blue,
    Color::Yellow,
    Color::Cyan,
    Color::Magenta,
    Color::Green,
];

fn color(context: usize) -> Color {
    COLORS[context % COLORS.len()].clone()
}

fn set_log_context(log_context: usize) {
    LOG_CONTEXT.with(|lc| *lc.borrow_mut() = Some(log_context));
}

fn clear_log_context() {
    LOG_CONTEXT.with(|lc| *lc.borrow_mut() = None);
}

pub fn log_init() {
    INIT.call_once(|| {
        let mut builder = env_logger::Builder::from_default_env();
        builder
            .format(|buf, record| {
                let mut style = buf.style();
                LOG_CONTEXT.with(|f| {
                    if let Some(lc) = *f.borrow() {
                        style.set_color(color(lc));
                        style.set_bold(true);
                    }
                });

                writeln!(buf, "{:5} {}", record.level(), style.value(record.args()))
            }).init();
    });
}

pub struct LogContextFuture<A>
where
    A: Future,
{
    log_context: usize,
    inner: A,
}

impl<A> LogContextFuture<A>
where
    A: Future,
{
    pub fn new(inner: A, log_context: usize) -> LogContextFuture<A>
    where
        A: Future,
    {
        LogContextFuture {
            log_context,
            inner: inner,
        }
    }
}

impl<A> Future for LogContextFuture<A>
where
    A: Future,
{
    type Item = A::Item;
    type Error = A::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        set_log_context(self.log_context);
        let result = self.inner.poll();
        clear_log_context();
        result
    }
}
