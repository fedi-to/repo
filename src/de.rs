
use serde::forward_to_deserialize_any;
use serde::de::DeserializeSeed;
use serde::de::Deserializer;
use serde::de::Error as _;
use serde::de::MapAccess;
use serde::de::Visitor;
use serde::de::value::BorrowedStrDeserializer;
use serde::de::value::U64Deserializer;

use crate::is_scheme_invalid;

/// Deserializer for the fedi-to cookie format.
pub struct CookieDeserializer<'a> {
    s: &'a str,
}

impl<'de> Deserializer<'de> for CookieDeserializer<'de> {
    type Error = serde::de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_map(self)
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

impl<'de> MapAccess<'de> for CookieDeserializer<'de> {
    type Error = serde::de::value::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        let news = self.s.trim_start_matches(|c: char| -> bool {
            lenient_scheme_toggle!(
                {
                    c.is_ascii_lowercase() || c == '-'
                },
                {
                    c.is_ascii_lowercase()
                }
            )
        });
        let s = &self.s[..self.s.len()-news.len()];
        if s.is_empty() != news.is_empty() {
            Err(Self::Error::custom(""))
        } else if s.is_empty() {
            Ok(None)
        } else if
            is_scheme_invalid(s)
            ||
            !news.starts_with(|c: char| -> bool { c.is_ascii_digit() })
        {
            Err(Self::Error::custom(""))
        } else {
            self.s = news;
            seed.deserialize(BorrowedStrDeserializer::new(s)).map(Some)
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        let news = self.s.trim_start_matches(|c: char| -> bool {
            c.is_ascii_digit()
        });
        let s = &self.s[..self.s.len()-news.len()];
        if s.is_empty() {
            Err(Self::Error::custom(""))
        } else {
            self.s = news;
            seed.deserialize(U64Deserializer::new(s.parse().unwrap()))
        } 
    }
}

impl<'de> CookieDeserializer<'de> {
    pub fn new(s: &'de str) -> Self {
        Self { s }
    }
}

#[cfg(test)]
mod tests {
}
