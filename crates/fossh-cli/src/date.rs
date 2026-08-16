#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateError;

impl std::fmt::Display for DateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "expected a date in YYYY-MM-DD form")
    }
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }).div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe.div_euclid(4) - yoe.div_euclid(100) + doy;
    era * 146_097 + doe - 719_468
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

pub fn parse_date(s: &str) -> Result<i64, DateError> {
    let bytes = s.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(DateError);
    }
    let digits_only = |part: &str| part.bytes().all(|b| b.is_ascii_digit()) && !part.is_empty();
    let (y_s, rest) = s.split_at(4);
    let rest = &rest[1..];
    let (m_s, d_s) = rest.split_at(2);
    let d_s = &d_s[1..];
    if !digits_only(y_s) || !digits_only(m_s) || !digits_only(d_s) {
        return Err(DateError);
    }
    let y: i64 = y_s.parse().map_err(|_| DateError)?;
    let m: u32 = m_s.parse().map_err(|_| DateError)?;
    let d: u32 = d_s.parse().map_err(|_| DateError)?;

    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return Err(DateError);
    }

    Ok(days_from_civil(y, m, d) * 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(parse_date("1970-01-01"), Ok(0));
    }

    #[test]
    fn one_non_leap_year_later() {
        assert_eq!(parse_date("1971-01-01"), Ok(365 * 86_400));
    }

    #[test]
    fn crosses_a_leap_day() {

        let start = parse_date("1972-01-01").unwrap();
        let end = parse_date("1973-01-01").unwrap();
        assert_eq!(end - start, 366 * 86_400);
    }

    #[test]
    fn century_non_leap_year_rule() {

        let start = parse_date("1900-01-01").unwrap();
        let end = parse_date("1901-01-01").unwrap();
        assert_eq!(end - start, 365 * 86_400);
    }

    #[test]
    fn quadricentennial_is_a_leap_year() {

        let start = parse_date("2000-01-01").unwrap();
        let end = parse_date("2001-01-01").unwrap();
        assert_eq!(end - start, 366 * 86_400);
    }

    #[test]
    fn consistent_with_manual_day_counting() {

        let leap_years_in_range = (1970..2026).filter(|&y| is_leap_year(y)).count();
        let days_to_2026 = 56 * 365 + leap_years_in_range as i64;
        assert_eq!(parse_date("2026-01-01"), Ok(days_to_2026 * 86_400));

        let days_jan_through_jul = 31 + 28 + 31 + 30 + 31 + 30 + 31;
        assert_eq!(
            parse_date("2026-08-01"),
            Ok((days_to_2026 + days_jan_through_jul) * 86_400)
        );
    }

    #[test]
    fn rejects_malformed_shapes() {
        assert!(parse_date("2026-8-1").is_err());
        assert!(parse_date("2026/08/01").is_err());
        assert!(parse_date("08-01-2026").is_err());
        assert!(parse_date("2026-08-01T00:00:00").is_err());
        assert!(parse_date("").is_err());
        assert!(parse_date("not-a-date").is_err());
    }

    #[test]
    fn rejects_nonexistent_dates() {
        assert!(parse_date("2026-02-30").is_err());
        assert!(parse_date("2026-02-29").is_err());
        assert!(parse_date("2024-02-29").is_ok());
        assert!(parse_date("2026-13-01").is_err());
        assert!(parse_date("2026-00-01").is_err());
        assert!(parse_date("2026-01-00").is_err());
        assert!(parse_date("2026-04-31").is_err());
    }
}
