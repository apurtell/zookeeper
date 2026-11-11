// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A two-way select with no runtime.
//!
//! The recipes wait for two things at once, for example a predecessor
//! watch and a session change. The crate has no futures crate and starts
//! no task, so this module gives the one combinator that it needs.
//!
//! Both futures are borrowed, so the future that loses the race stays
//! with the caller and keeps its state. The client futures that the
//! recipes race (`OneshotWatcher`, `Next`, `Changed`, `ResponseFuture`)
//! are cancel-safe and `Unpin`.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// The result of [`select`].
#[derive(Debug)]
pub(crate) enum Either<A, B> {
    /// The first future completed first.
    Left(A),
    /// The second future completed first.
    Right(B),
}

/// Waits until one of two futures completes. When both are ready in
/// one poll, the first one wins.
pub(crate) async fn select<A, B>(a: &mut A, b: &mut B) -> Either<A::Output, B::Output>
where
    A: Future + Unpin,
    B: Future + Unpin,
{
    poll_fn(|cx| {
        if let Poll::Ready(v) = Pin::new(&mut *a).poll(cx) {
            return Poll::Ready(Either::Left(v));
        }
        if let Poll::Ready(v) = Pin::new(&mut *b).poll(cx) {
            return Poll::Ready(Either::Right(v));
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::future::{pending, ready};
    use std::task::{Context, Waker};

    use super::*;

    fn poll_once<F: Future>(f: F) -> Poll<F::Output> {
        let mut f = std::pin::pin!(f);
        f.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn first_ready_wins() {
        let (mut a, mut b) = (ready(1), ready(2));
        assert!(matches!(
            poll_once(select(&mut a, &mut b)),
            Poll::Ready(Either::Left(1))
        ));
        let (mut a, mut b) = (pending::<i32>(), ready(2));
        assert!(matches!(
            poll_once(select(&mut a, &mut b)),
            Poll::Ready(Either::Right(2))
        ));
        let (mut a, mut b) = (pending::<i32>(), pending::<i32>());
        assert!(poll_once(select(&mut a, &mut b)).is_pending());
    }
}
