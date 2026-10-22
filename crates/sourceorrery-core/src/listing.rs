//! Paged listings: [`ListOptions`], [`Page`] and the [`ContinuationToken`]
//! that links one page to the next.
//!
//! Listings are ordered by secret name. A page is a window over that
//! order: up to `max_results` items whose names sort after the
//! continuation token, and a token of its own, the name of its last item,
//! while names remain after it. Because the token is a name and not an
//! offset, a secret created or deleted while a caller pages through the
//! vault appears or disappears according to where its name sorts; nothing
//! is returned twice and nothing outside the changed name is skipped. A
//! backend decides whether names remain without verifying them, so the
//! final page may hold fewer items than `max_results`, even none: page
//! until the token is `None`.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SecretError};
use crate::secret::validate_secret_name;

/// Where a listing stopped: the last name of the previous page.
///
/// Opaque to callers, who pass it back unchanged; its text is a secret
/// name, so it never carries a value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContinuationToken(String);

impl ContinuationToken {
    /// Wrap the last name of a page.
    pub fn new(last_name: impl Into<String>) -> Self {
        Self(last_name.into())
    }

    /// The token's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A token is a secret name; anything else is `invalid_argument`.
    pub fn validate(&self) -> Result<()> {
        validate_secret_name(&self.0).map_err(|_| {
            SecretError::InvalidArgument("continuation token is not a secret name".to_owned())
        })
    }
}

impl std::fmt::Display for ContinuationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How much of a listing to return, and from where.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListOptions {
    /// Most items in the page. `None` means every remaining item; `Some(0)`
    /// is `invalid_argument`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<usize>,
    /// Resume after this token, from a previous page. `None` starts at the
    /// first name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<ContinuationToken>,
}

impl ListOptions {
    /// The first page of at most `max_results` items.
    pub fn first(max_results: usize) -> Self {
        Self {
            max_results: Some(max_results),
            continuation: None,
        }
    }

    /// Check the options; the backend records a failure for a rejected call.
    pub fn validate(&self) -> Result<()> {
        if self.max_results == Some(0) {
            return Err(SecretError::InvalidArgument(
                "max_results must be at least 1".to_owned(),
            ));
        }
        if let Some(token) = &self.continuation {
            token.validate()?;
        }
        Ok(())
    }

    /// The name every item in the page must sort after.
    pub fn after(&self) -> Option<&str> {
        self.continuation.as_ref().map(ContinuationToken::as_str)
    }

    /// The page size as a bound, `usize::MAX` for no bound.
    pub fn limit(&self) -> usize {
        self.max_results.unwrap_or(usize::MAX)
    }
}

/// One page of a listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// The items, in name order.
    pub items: Vec<T>,
    /// Pass to the next call to get the page after this one; `None` when
    /// this is the last page. A page with a token holds `max_results`
    /// items; the page after the last token may hold fewer, even none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<ContinuationToken>,
}

impl<T> Page<T> {
    /// Cut one page out of a complete listing that is already sorted by
    /// `name`. This is what the default paged methods of `SecretClient`
    /// use; a backend that can bound its work to the window overrides them.
    pub fn from_sorted(
        items: Vec<T>,
        options: &ListOptions,
        name: impl Fn(&T) -> &str,
    ) -> Result<Self> {
        options.validate()?;
        let after = options.after();
        let mut remaining = items
            .into_iter()
            .filter(|item| after.is_none_or(|after| name(item) > after))
            .peekable();
        let page: Vec<T> = remaining.by_ref().take(options.limit()).collect();
        let continuation = if remaining.peek().is_some() {
            page.last().map(|last| ContinuationToken::new(name(last)))
        } else {
            None
        };
        Ok(Self {
            items: page,
            continuation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(page: &Page<String>) -> Vec<&str> {
        page.items.iter().map(String::as_str).collect()
    }

    #[test]
    fn pages_cover_a_sorted_listing_exactly_once() {
        let all: Vec<String> = ["a", "b", "c", "d", "e"].map(str::to_owned).into();
        let mut options = ListOptions::first(2);
        let mut seen = Vec::new();
        loop {
            let page = Page::from_sorted(all.clone(), &options, String::as_str).unwrap();
            assert!(page.items.len() <= 2);
            seen.extend(page.items.iter().cloned());
            match page.continuation {
                Some(token) => {
                    assert_eq!(token.as_str(), seen.last().unwrap());
                    options.continuation = Some(token);
                }
                None => break,
            }
        }
        assert_eq!(seen, all);
    }

    #[test]
    fn last_page_has_no_continuation_even_when_full() {
        let all: Vec<String> = ["a", "b"].map(str::to_owned).into();
        let page = Page::from_sorted(all, &ListOptions::first(2), String::as_str).unwrap();
        assert_eq!(names(&page), ["a", "b"]);
        assert_eq!(page.continuation, None);
    }

    #[test]
    fn no_limit_returns_everything_after_the_token() {
        let all: Vec<String> = ["a", "b", "c"].map(str::to_owned).into();
        let options = ListOptions {
            max_results: None,
            continuation: Some(ContinuationToken::new("a")),
        };
        let page = Page::from_sorted(all, &options, String::as_str).unwrap();
        assert_eq!(names(&page), ["b", "c"]);
        assert_eq!(page.continuation, None);
    }

    #[test]
    fn options_are_validated() {
        assert_eq!(
            ListOptions::first(0).validate().unwrap_err().code(),
            "invalid_argument"
        );
        let bad = ListOptions {
            max_results: None,
            continuation: Some(ContinuationToken::new("not a name!")),
        };
        assert_eq!(bad.validate().unwrap_err().code(), "invalid_argument");
        assert_eq!(
            Page::<String>::from_sorted(Vec::new(), &bad, String::as_str)
                .unwrap_err()
                .code(),
            "invalid_argument"
        );
    }

    #[test]
    fn token_serialises_as_its_text() {
        let page = Page {
            items: vec!["x".to_owned()],
            continuation: Some(ContinuationToken::new("x")),
        };
        assert_eq!(
            serde_json::to_string(&page).unwrap(),
            r#"{"items":["x"],"continuation":"x"}"#
        );
        let last: Page<String> = serde_json::from_str(r#"{"items":[]}"#).unwrap();
        assert_eq!(last.continuation, None);
    }
}
