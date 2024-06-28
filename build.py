import os
import sys
import glob


def main():
    base = sys.argv[1]
    build_filename = "build.ninja"

    with open(build_filename, "w") as fp:
        link_files = [
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libm.so.6",
            "/usr/lib/x86_64-linux-gnu/crt1.o",
        ]
        fp.write(
            f"""
rule cc-clang
    command = clang-13 \
            -fPIC -fno-lto -fno-direct-access-external-data \
            -c $in -o $out

rule cc-gcc
    command = gcc -fPIC -c $in -o $out

rule cc-clang-musl
    command = clang-13 \
            -I/usr/include/x86_64-linux-musl \
            -fPIC -fno-lto -fno-direct-access-external-data \
            -c $in -o $out

rule cc-gcc-musl
    command = gcc -I/usr/include/x86_64-linux-musl -fPIC -c $in -o $out

rule build-link
    command = cargo build --release

rule link
    command = target/release/link -v --link -o $out $in {" ".join(link_files)}

rule run
    command = $in > $out

rule diff
    command = diff -q $in

build target/release/link: build-link

"""
        )
        generate_testfiles(fp)
        generate_c_testsuite(base, "cc-clang", "clang-glibc", fp)
        generate_c_testsuite(base, "cc-clang-musl", "clang-musl", fp)
        generate_c_testsuite(base, "cc-gcc-musl", "gcc-musl", fp)
        generate_c_testsuite(base, "cc-gcc", "gcc-glibc", fp)


def generate_testfiles(fp):
    input_directory = "testfiles"
    outputs = []

    def gen_with_rule(target, rule):
        for f in glob.glob(os.path.join(input_directory, "*.c")):
            directory, filename = os.path.split(f)
            base, ext = os.path.splitext(filename)
            input_filename = os.path.join(input_directory, filename)
            output_filename = os.path.join(target, f"{base}.o")
            fp.write(f"build {output_filename}: {rule} {input_filename}\n")
            outputs.append(output_filename)

    gen_with_rule(os.path.join("build", "clang-glibc"), "cc-clang")
    gen_with_rule(os.path.join("build", "clang-musl"), "cc-clang-musl")
    gen_with_rule(os.path.join("build", "gcc-glibc"), "cc-gcc")
    gen_with_rule(os.path.join("build", "gcc-musl"), "cc-gcc-musl")

    fp.write(f"build testfiles: phony {' '.join(outputs)}\n")
    fp.write("default testfiles\n")


def generate_c_testsuite(base, rule, build_type, fp):
    i = 1
    output = os.path.join("build", "c-testsuite", build_type)
    os.makedirs(output, exist_ok=True)
    outputs = []
    while True:
        filename = os.path.join(base, "%05d.c" % i)
        if not os.path.exists(filename):
            break

        number, ext = os.path.splitext(filename)
        output_filename = os.path.join(output, "%05d.o" % i)
        output_exe = os.path.join(output, "%05d.exe" % i)
        expected_filename = f"{filename}.expected"
        output_result = os.path.join(output, "%05d.c.results" % i)
        assert os.path.exists(expected_filename)
        link_exe = "target/release/link"

        # skip broken tests
        if i in [143, 189]:
            i += 1
            continue

        outputs.append(f"{build_type}/{i}")
        fp.write(f"build {output_filename}: {rule} {filename}\n")
        fp.write(f"build {output_exe}: link {output_filename} | {link_exe}\n")
        fp.write(f"build {output_result}: run {output_exe}\n")
        fp.write(
            f"""build {filename}-{build_type}-diff: diff {filename}.expected {output_result}\n"""
        )
        fp.write(f"build {build_type}/{i}: phony {filename} | {output_result}\n")
        i += 1

    fp.write(f"build testsuite-{build_type}: phony {' '.join(outputs)}\n")
    fp.write(f"default testsuite-{build_type}\n")


if __name__ == "__main__":
    main()
