from filename_recovery import recover_names_from_includes


def test_unique_include_recovers_lost_underscores() -> None:
    files = [
        ("src/kernelv1.cu", "int kernel() {}\n"),
        ("src/main.cpp", '#include "kernel_v1.cu"\n'),
    ]
    assert recover_names_from_includes(files)[0][0] == "src/kernel_v1.cu"


def test_ambiguous_include_leaves_name_unchanged() -> None:
    files = [
        ("src/kernelv1.cu", "int kernel() {}\n"),
        ("src/a.cpp", '#include "kernel_v1.cu"\n'),
        ("src/b.cpp", '#include "kernel-v1.cu"\n'),
    ]
    assert recover_names_from_includes(files)[0][0] == "src/kernelv1.cu"
