use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CompiledRegex {
    pub pattern: String,
    pub cflags: i32,
    pub sub_count: usize,
}

pub fn count_capture_groups(pat: &str) -> usize {
    let mut count = 0;
    let mut escaped = false;
    for c in pat.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '(' {
            count += 1;
        }
    }
    count
}

#[derive(Debug, Clone)]
enum RxAtom {
    Char(char),
    Any,
    Class(Vec<(char, char)>, bool),
    Group(usize, Vec<RxSeq>),
}

#[derive(Debug, Clone)]
enum RxItem {
    Exact(RxAtom),
    ZeroOrMore(RxAtom),
    OneOrMore(RxAtom),
    ZeroOrOne(RxAtom),
}

#[derive(Debug, Clone)]
struct RxSeq {
    items: Vec<RxItem>,
}

struct RxParser {
    group_counter: usize,
}

impl RxParser {
    fn new() -> Self {
        Self { group_counter: 1 }
    }

    fn parse_alts(&mut self, s: &[char]) -> Vec<RxSeq> {
        let mut parts = Vec::new();
        let mut depth = 0;
        let mut cur = Vec::new();
        for &c in s {
            if c == '(' {
                depth += 1;
                cur.push(c);
            } else if c == ')' {
                if depth > 0 {
                    depth -= 1;
                }
                cur.push(c);
            } else if c == '|' && depth == 0 {
                parts.push(cur);
                cur = Vec::new();
            } else {
                cur.push(c);
            }
        }
        parts.push(cur);
        parts.into_iter().map(|p| self.parse_seq(&p)).collect()
    }

    fn parse_seq(&mut self, chars: &[char]) -> RxSeq {
        let mut items = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let atom = if c == '(' {
                let mut depth = 1;
                let mut j = i + 1;
                while j < chars.len() && depth > 0 {
                    if chars[j] == '(' {
                        depth += 1;
                    } else if chars[j] == ')' {
                        depth -= 1;
                    }
                    j += 1;
                }
                let inner = if j > i + 1 { &chars[i + 1..j - 1] } else { &[] };
                let gid = self.group_counter;
                self.group_counter += 1;
                let alts = self.parse_alts(inner);
                i = j;
                RxAtom::Group(gid, alts)
            } else if c == '[' {
                let mut j = i + 1;
                if j < chars.len() && (chars[j] == '^' || chars[j] == '!') {
                    j += 1;
                }
                if j < chars.len() && chars[j] == ']' {
                    j += 1;
                }
                while j < chars.len() && chars[j] != ']' {
                    j += 1;
                }
                let inner = if j <= chars.len() { &chars[i + 1..j] } else { &[] };
                let (neg, range_chars) = if !inner.is_empty() && (inner[0] == '^' || inner[0] == '!') {
                    (true, &inner[1..])
                } else {
                    (false, inner)
                };
                let mut ranges = Vec::new();
                let mut k = 0;
                while k < range_chars.len() {
                    if k + 2 < range_chars.len() && range_chars[k + 1] == '-' {
                        ranges.push((range_chars[k], range_chars[k + 2]));
                        k += 3;
                    } else {
                        ranges.push((range_chars[k], range_chars[k]));
                        k += 1;
                    }
                }
                i = if j < chars.len() { j + 1 } else { j };
                RxAtom::Class(ranges, neg)
            } else if c == '\\' {
                i += 1;
                let atom = if i < chars.len() {
                    match chars[i] {
                        'd' => RxAtom::Class(vec![('0', '9')], false),
                        'w' => RxAtom::Class(vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')], false),
                        's' => RxAtom::Class(vec![(' ', ' '), ('\t', '\t'), ('\n', '\n'), ('\r', '\r')], false),
                        other => RxAtom::Char(other),
                    }
                } else {
                    RxAtom::Char('\\')
                };
                i += 1;
                atom
            } else if c == '.' {
                i += 1;
                RxAtom::Any
            } else {
                i += 1;
                RxAtom::Char(c)
            };

            // Check quantifier
            if i < chars.len() {
                match chars[i] {
                    '*' => {
                        items.push(RxItem::ZeroOrMore(atom));
                        i += 1;
                    }
                    '+' => {
                        items.push(RxItem::OneOrMore(atom));
                        i += 1;
                    }
                    '?' => {
                        items.push(RxItem::ZeroOrOne(atom));
                        i += 1;
                    }
                    _ => items.push(RxItem::Exact(atom)),
                }
            } else {
                items.push(RxItem::Exact(atom));
            }
        }
        RxSeq { items }
    }
}

pub fn regex_match_internal(
    pattern: &str,
    text: &str,
    cflags: i32,
) -> Option<HashMap<usize, (usize, usize)>> {
    let icase = (cflags & 2) != 0;
    let pat_chars: Vec<char> = pattern.chars().collect();
    if pat_chars.is_empty() {
        let mut caps = HashMap::new();
        caps.insert(0, (0, 0));
        return Some(caps);
    }

    let anchored_start = pat_chars[0] == '^';
    let anchored_end = pat_chars.len() > (if anchored_start { 1 } else { 0 })
        && pat_chars[pat_chars.len() - 1] == '$';

    let start_idx = if anchored_start { 1 } else { 0 };
    let end_idx = if anchored_end { pat_chars.len() - 1 } else { pat_chars.len() };
    let body = &pat_chars[start_idx..end_idx];

    let mut parser = RxParser::new();
    let alts = parser.parse_alts(body);

    let text_chars: Vec<char> = text.chars().collect();
    let search_range = if anchored_start {
        0..=0
    } else {
        0..=text_chars.len()
    };

    for st in search_range {
        let mut caps = HashMap::new();
        if let Some(end_pos) = match_alts(&alts, &text_chars, st, icase, &mut caps) {
            if !anchored_end || end_pos == text_chars.len() {
                caps.insert(0, (st, end_pos));
                return Some(caps);
            }
        }
    }
    None
}

fn match_alts(
    alts: &[RxSeq],
    chars: &[char],
    idx: usize,
    icase: bool,
    caps: &mut HashMap<usize, (usize, usize)>,
) -> Option<usize> {
    for alt in alts {
        let mut cur_caps = caps.clone();
        if let Some(pos) = match_seq(&alt.items, chars, idx, icase, &mut cur_caps) {
            *caps = cur_caps;
            return Some(pos);
        }
    }
    None
}

fn match_seq(
    items: &[RxItem],
    chars: &[char],
    idx: usize,
    icase: bool,
    caps: &mut HashMap<usize, (usize, usize)>,
) -> Option<usize> {
    if items.is_empty() {
        return Some(idx);
    }
    let (first, rest) = (&items[0], &items[1..]);
    match first {
        RxItem::Exact(atom) => {
            let matches = match_atom(atom, chars, idx, icase, caps);
            for (nxt, nxt_caps) in matches {
                let mut branch_caps = nxt_caps;
                if let Some(end) = match_seq(rest, chars, nxt, icase, &mut branch_caps) {
                    *caps = branch_caps;
                    return Some(end);
                }
            }
            None
        }
        RxItem::ZeroOrOne(atom) => {
            let matches = match_atom(atom, chars, idx, icase, caps);
            for (nxt, nxt_caps) in matches {
                let mut branch_caps = nxt_caps;
                if let Some(end) = match_seq(rest, chars, nxt, icase, &mut branch_caps) {
                    *caps = branch_caps;
                    return Some(end);
                }
            }
            let mut skip_caps = caps.clone();
            if let Some(end) = match_seq(rest, chars, idx, icase, &mut skip_caps) {
                *caps = skip_caps;
                return Some(end);
            }
            None
        }
        RxItem::ZeroOrMore(atom) => {
            // Collect greedy matches
            let mut states = vec![(idx, caps.clone())];
            let mut cur_pos = idx;
            let mut cur_caps = caps.clone();
            while cur_pos <= chars.len() {
                let matches = match_atom(atom, chars, cur_pos, icase, &cur_caps);
                if matches.is_empty() || matches[0].0 == cur_pos {
                    break;
                }
                cur_pos = matches[0].0;
                cur_caps = matches[0].1.clone();
                states.push((cur_pos, cur_caps.clone()));
            }
            // Try in reverse order (greedy)
            for (p, c) in states.into_iter().rev() {
                let mut branch_caps = c;
                if let Some(end) = match_seq(rest, chars, p, icase, &mut branch_caps) {
                    *caps = branch_caps;
                    return Some(end);
                }
            }
            None
        }
        RxItem::OneOrMore(atom) => {
            let mut states = Vec::new();
            let mut cur_pos = idx;
            let mut cur_caps = caps.clone();
            while cur_pos <= chars.len() {
                let matches = match_atom(atom, chars, cur_pos, icase, &cur_caps);
                if matches.is_empty() || matches[0].0 == cur_pos {
                    break;
                }
                cur_pos = matches[0].0;
                cur_caps = matches[0].1.clone();
                states.push((cur_pos, cur_caps.clone()));
            }
            for (p, c) in states.into_iter().rev() {
                let mut branch_caps = c;
                if let Some(end) = match_seq(rest, chars, p, icase, &mut branch_caps) {
                    *caps = branch_caps;
                    return Some(end);
                }
            }
            None
        }
    }
}

fn match_atom(
    atom: &RxAtom,
    chars: &[char],
    pos: usize,
    icase: bool,
    caps: &HashMap<usize, (usize, usize)>,
) -> Vec<(usize, HashMap<usize, (usize, usize)>)> {
    match atom {
        RxAtom::Char(lit) => {
            if pos < chars.len() {
                let c = if icase { chars[pos].to_ascii_lowercase() } else { chars[pos] };
                let l = if icase { lit.to_ascii_lowercase() } else { *lit };
                if c == l {
                    return vec![(pos + 1, caps.clone())];
                }
            }
            vec![]
        }
        RxAtom::Any => {
            if pos < chars.len() && chars[pos] != '\n' {
                vec![(pos + 1, caps.clone())]
            } else {
                vec![]
            }
        }
        RxAtom::Class(ranges, neg) => {
            if pos < chars.len() {
                let c = if icase { chars[pos].to_ascii_lowercase() } else { chars[pos] };
                let mut matched = false;
                for &(st, en) in ranges {
                    let s = if icase { st.to_ascii_lowercase() } else { st };
                    let e = if icase { en.to_ascii_lowercase() } else { en };
                    if c >= s && c <= e {
                        matched = true;
                        break;
                    }
                }
                if matched != *neg {
                    return vec![(pos + 1, caps.clone())];
                }
            }
            vec![]
        }
        RxAtom::Group(gid, alts) => {
            let mut results = Vec::new();
            for alt in alts {
                let mut cur_caps = caps.clone();
                if let Some(end_pos) = match_seq(&alt.items, chars, pos, icase, &mut cur_caps) {
                    cur_caps.insert(*gid, (pos, end_pos));
                    results.push((end_pos, cur_caps));
                }
            }
            results
        }
    }
}

pub fn fnmatch_internal(pattern: &str, string: &str, flags: i32) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let str_chars: Vec<char> = string.chars().collect();
    let noescape = (flags & 1) != 0;
    let pathname = (flags & 2) != 0;
    let casefold = (flags & 0x10) != 0;

    fn match_rec(
        pat: &[char],
        p_idx: usize,
        s: &[char],
        s_idx: usize,
        noescape: bool,
        pathname: bool,
        casefold: bool,
    ) -> bool {
        let mut p = p_idx;
        let mut s_pos = s_idx;

        while p < pat.len() {
            match pat[p] {
                '*' => {
                    let mut next_s = s_pos;
                    while next_s <= s.len() {
                        if match_rec(pat, p + 1, s, next_s, noescape, pathname, casefold) {
                            return true;
                        }
                        if next_s < s.len() {
                            if pathname && s[next_s] == '/' {
                                break;
                            }
                            next_s += 1;
                        } else {
                            break;
                        }
                    }
                    return false;
                }
                '?' => {
                    if s_pos >= s.len() {
                        return false;
                    }
                    if pathname && s[s_pos] == '/' {
                        return false;
                    }
                    p += 1;
                    s_pos += 1;
                }
                '[' => {
                    if s_pos >= s.len() {
                        return false;
                    }
                    if pathname && s[s_pos] == '/' {
                        return false;
                    }
                    let mut closing = p + 1;
                    if closing < pat.len() && (pat[closing] == '!' || pat[closing] == '^') {
                        closing += 1;
                    }
                    if closing < pat.len() && pat[closing] == ']' {
                        closing += 1;
                    }
                    while closing < pat.len() && pat[closing] != ']' {
                        closing += 1;
                    }
                    if closing >= pat.len() {
                        let sc = if casefold { s[s_pos].to_ascii_lowercase() } else { s[s_pos] };
                        let pc = if casefold { pat[p].to_ascii_lowercase() } else { pat[p] };
                        if sc != pc {
                            return false;
                        }
                        p += 1;
                        s_pos += 1;
                    } else {
                        let class_content = &pat[p + 1..closing];
                        let (negated, range_chars) = if !class_content.is_empty()
                            && (class_content[0] == '!' || class_content[0] == '^')
                        {
                            (true, &class_content[1..])
                        } else {
                            (false, class_content)
                        };
                        let sc = if casefold { s[s_pos].to_ascii_lowercase() } else { s[s_pos] };
                        let mut matched = false;
                        let mut i = 0;
                        while i < range_chars.len() {
                            if i + 2 < range_chars.len() && range_chars[i + 1] == '-' {
                                let st = if casefold {
                                    range_chars[i].to_ascii_lowercase()
                                } else {
                                    range_chars[i]
                                };
                                let en = if casefold {
                                    range_chars[i + 2].to_ascii_lowercase()
                                } else {
                                    range_chars[i + 2]
                                };
                                if sc >= st && sc <= en {
                                    matched = true;
                                    break;
                                }
                                i += 3;
                            } else {
                                let c = if casefold {
                                    range_chars[i].to_ascii_lowercase()
                                } else {
                                    range_chars[i]
                                };
                                if sc == c {
                                    matched = true;
                                    break;
                                }
                                i += 1;
                            }
                        }
                        if matched == negated {
                            return false;
                        }
                        p = closing + 1;
                        s_pos += 1;
                    }
                }
                '\\' if !noescape => {
                    p += 1;
                    if p >= pat.len() || s_pos >= s.len() {
                        return false;
                    }
                    let sc = if casefold { s[s_pos].to_ascii_lowercase() } else { s[s_pos] };
                    let pc = if casefold { pat[p].to_ascii_lowercase() } else { pat[p] };
                    if sc != pc {
                        return false;
                    }
                    p += 1;
                    s_pos += 1;
                }
                c => {
                    if s_pos >= s.len() {
                        return false;
                    }
                    let sc = if casefold { s[s_pos].to_ascii_lowercase() } else { s[s_pos] };
                    let pc = if casefold { c.to_ascii_lowercase() } else { c };
                    if sc != pc {
                        return false;
                    }
                    p += 1;
                    s_pos += 1;
                }
            }
        }
        s_pos == s.len()
    }

    match_rec(&pat, 0, &str_chars, 0, noescape, pathname, casefold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_matching() {
        let m = regex_match_internal("^[0-9]+$", "12345", 0);
        assert!(m.is_some());
        assert_eq!(m.unwrap().get(&0), Some(&(0, 5)));

        let m2 = regex_match_internal("([a-z]+):([0-9]+)", "host:8080", 0);
        assert!(m2.is_some());
        let caps = m2.unwrap();
        assert_eq!(caps.get(&0), Some(&(0, 9)));
        assert_eq!(caps.get(&1), Some(&(0, 4)));
        assert_eq!(caps.get(&2), Some(&(5, 9)));

        let m3 = regex_match_internal("hello", "HELLO", 2); // REG_ICASE
        assert!(m3.is_some());
    }

    #[test]
    fn test_fnmatch() {
        assert!(fnmatch_internal("*.png", "texture.png", 0));
        assert!(!fnmatch_internal("*.png", "texture.jpg", 0));
        assert!(fnmatch_internal("lib*.so", "libwalzer32.so", 0));
        assert!(fnmatch_internal("[a-z]*", "apple", 0));
    }
}
