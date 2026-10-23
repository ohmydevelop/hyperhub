//! Windows file effects are sets: one operation must not hide another.
//! Kept independent of Win32 APIs so permission combinations run on every host.
use crate::FileSandboxOperation as Operation;

pub(crate) fn open(access: u32, disposition: Option<u32>, options: u32) -> Vec<Operation> {
    let mut operations = Vec::new();
    if matches!(disposition, Some(0 | 2 | 3 | 5)) {
        operations.push(Operation::Create);
    }
    // FILE_READ_DATA, FILE_READ_EA and FILE_EXECUTE disclose file content.
    // GENERIC_READ/EXECUTE/ALL and MAXIMUM_ALLOWED can grant those rights.
    if access & 0xB200_0029 != 0 {
        operations.push(Operation::Read);
    }
    // Preserve write-data/append/EA/attribute checks and expand generic rights.
    if access & 0x5200_0116 != 0 || matches!(disposition, Some(0 | 4 | 5)) {
        operations.push(Operation::Write);
    }
    if options & 0x1000 != 0 || disposition == Some(0) {
        operations.push(Operation::Delete);
    }
    operations
}

pub(crate) fn mapping(protection: u32) -> Vec<Operation> {
    // Every file mapping retains its existing Read check, including NOACCESS
    // and image mappings whose requested page protection the OS can ignore.
    let mut operations = vec![Operation::Read];
    if protection & (0x04 | 0x08 | 0x40 | 0x80) != 0 {
        operations.push(Operation::Write);
    }
    operations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_content_rights_are_combined_without_losing_read_or_write() {
        let singles = [
            (0x0000_0001, vec![Operation::Read]),
            (0x0000_0002, vec![Operation::Write]),
            (0x0000_0004, vec![Operation::Write]),
            (0x0000_0008, vec![Operation::Read]),
            (0x0000_0010, vec![Operation::Write]),
            (0x0000_0020, vec![Operation::Read]),
            (0x0000_0080, vec![]),
            (0x0000_0100, vec![Operation::Write]),
            (0x8000_0000, vec![Operation::Read]),
            (0x4000_0000, vec![Operation::Write]),
            (0x2000_0000, vec![Operation::Read]),
            (0x1000_0000, vec![Operation::Read, Operation::Write]),
            (0x0200_0000, vec![Operation::Read, Operation::Write]),
        ];
        for (left, left_expected) in &singles {
            assert_eq!(open(*left, None, 0), *left_expected);
            for (right, right_expected) in &singles {
                let expected: Vec<_> = [Operation::Read, Operation::Write]
                    .into_iter()
                    .filter(|op| left_expected.contains(op) || right_expected.contains(op))
                    .collect();
                assert_eq!(
                    open(left | right, None, 0),
                    expected,
                    "access={:#x}",
                    left | right
                );
            }
        }
    }

    #[test]
    fn creation_dispositions_add_effects_without_hiding_requested_read() {
        let cases = [
            (None, vec![]),
            (
                Some(0),
                vec![Operation::Create, Operation::Write, Operation::Delete],
            ),
            (Some(1), vec![]),
            (Some(2), vec![Operation::Create]),
            (Some(3), vec![Operation::Create]),
            (Some(4), vec![Operation::Write]),
            (Some(5), vec![Operation::Create, Operation::Write]),
        ];
        for (disposition, effects) in cases {
            assert_eq!(open(0x80, disposition, 0), effects);
            let mut combined = effects;
            let index = usize::from(combined.first() == Some(&Operation::Create));
            combined.insert(index, Operation::Read);
            assert_eq!(open(1, disposition, 0), combined);
        }
    }

    #[test]
    fn deletion_is_checked_for_effects_rather_than_requested_handle_rights() {
        assert_eq!(open(0x0001_0080, None, 0), vec![]);
        assert_eq!(open(0x80, None, 0x1000), vec![Operation::Delete]);
        assert_eq!(
            open(3, Some(3), 0x1000),
            vec![
                Operation::Create,
                Operation::Read,
                Operation::Write,
                Operation::Delete
            ]
        );
        assert_eq!(
            open(0x80, Some(0), 0),
            vec![Operation::Create, Operation::Write, Operation::Delete]
        );
    }

    #[test]
    fn writable_and_copy_on_write_mapping_modes_always_include_read() {
        for modifier in [0, 0x100, 0x200, 0x400, 0x4000_0000] {
            for protection in [0x04, 0x08, 0x40, 0x80] {
                assert_eq!(
                    mapping(protection | modifier),
                    vec![Operation::Read, Operation::Write]
                );
            }
            for protection in [0, 0x01, 0x02, 0x10, 0x20] {
                assert_eq!(mapping(protection | modifier), vec![Operation::Read]);
            }
        }
    }
}
