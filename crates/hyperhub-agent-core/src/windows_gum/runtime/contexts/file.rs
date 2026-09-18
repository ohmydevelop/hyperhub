#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::windows_gum) enum FileOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
}
pub(in crate::windows_gum) struct FileOperationContext {
    pub(in crate::windows_gum) operation: FileOperation,
    pub(in crate::windows_gum) path: Option<String>,
    pub(in crate::windows_gum) _handle: usize,
    pub(in crate::windows_gum) result: i32,
}
