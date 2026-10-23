//! Dates for the command line and the notices the library words.

/// Days since 1970-01-01 for a UTC date `YYYY-MM-DD` (`esp-schedule --by`).
///
/// The same rule as fsp-mint's date parser; it is copied here so the wallet
/// does not need fsp-mint for it.
pub fn parse_date(text: &str) -> Result<u64, String> {
    let bad = || format!("`{text}` is not a date: use YYYY-MM-DD");
    let parts: Vec<&str> = text.trim().split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return Err(bad());
    }
    let y: i64 = parts[0].parse().map_err(|_| bad())?;
    let m: i64 = parts[1].parse().map_err(|_| bad())?;
    let d: i64 = parts[2].parse().map_err(|_| bad())?;
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || d < 1 || d > dim[(m - 1) as usize] {
        return Err(bad());
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146097 + doe - 719468) as u64)
}

/// `secs` (Unix time) as `2026-10-28 14:03 UTC`.
pub fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // days since 1970-01-01 to a civil date (H. Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3_600,
        rest % 3_600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(parse_date("1970-01-01"), Ok(0));
        assert_eq!(parse_date("2000-03-01"), Ok(11_017));
        assert_eq!(parse_date("2024-02-29"), Ok(19_782));
        assert_eq!(parse_date("2026-10-16"), Ok(20_742));
        assert_eq!(parse_date(" 2026-10-16 "), Ok(20_742));
        assert_eq!(parse_date("9999-12-31"), Ok(2_932_896));
    }

    #[test]
    fn a_time_is_written_as_a_utc_date_and_minute() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(86_399), "1970-01-01 23:59 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(1_800_000_000), "2027-01-15 08:00 UTC");
        assert_eq!(format_utc(1_791_571_184), "2026-10-09 18:39 UTC");
    }

    #[test]
    fn bad_dates_are_refused() {
        for text in [
            "",
            "x",
            "2026-1-01",
            "2026-10-1",
            "26-10-16",
            "2026-02-29",
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "2026-10-00",
            "1969-12-31",
            "2026/10/16",
        ] {
            assert!(parse_date(text).is_err(), "{text}");
        }
    }
}
