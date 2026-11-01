use std::env;
use std::fs;
use std::process;
use transd_cli::{adb, apk_cmd, bench, info, package, runner};

fn print_usage() {
    println!(
        r#"transd-cli {} - In-Process Dynamic Binary Translator for 32-bit ARM on ARM64

USAGE:
    transd-cli <COMMAND> [OPTIONS]

COMMANDS:
    info <file.so>
        Inspect 32-bit ELF headers, segments, dependencies, and exported symbols

    run <file.so> [OPTIONS]
        Execute a 32-bit ARM shared library in the DBT runtime
        Options:
            --func <name>     Exported function name to call (default: JNI_OnLoad)
            --args <a,b,...>  Comma-separated 32-bit integer arguments

    apk <file.apk> [OPTIONS]
        Inspect and execute an Android APK package
        Options:
            --run             Extract and execute the primary 32-bit ARM native library
            --lib <name.so>   Specify which .so inside the APK to execute
            --func <name>     Function/JNI symbol to invoke
            --args <a,b,...>  Comma-separated integer arguments

    devices
        Inspect connected Android devices via ADB to determine 32-bit vs ARM64-only status

    package <file.apk> [OPTIONS]
        Repackage a 32-bit ARM APK to run on ARM64-only devices
        Options:
            -o, --output <file.apk>   Output repackaged APK path
            --bridge <path.so>        Custom host arm64-v8a libtransd.so
            --primary-lib <name.so>   Specify primary 32-bit native library
            --align <bytes>           Alignment for .so files (default: 4096)
            --config <k=v>            Extra properties for transd_config.prop

    test-device [OPTIONS]
        Test connected Android device capabilities and APK compatibility
        Options:
            -s, --device <id>         Target device serial
            --apk <file.apk>          Test compatibility of a specific APK

    install <file.apk> [OPTIONS]
        Install an APK onto a connected Android device via ADB
        Options:
            -s, --device <id>         Target device serial

    launch <pkg_or_apk> [OPTIONS]
        Launch an installed application or APK on a connected Android device
        Options:
            -s, --device <id>         Target device serial
            --activity <name>         Activity name to launch (auto-detected for APK)

    bench <file.so> [OPTIONS]
        Benchmark execution throughput (MIPS), compilation latency, and JIT caching
        Options:
            --func <name>     Function to benchmark
            --args <a,b,...>  Comma-separated integer arguments
            --iter <count>    Number of benchmark iterations (default: 100)

    help
        Print this help message

EXAMPLES:
    transd-cli info libnative.so
    transd-cli run libcalc.so --func add_and_square --args 3,4
    transd-cli bench libcalc.so --func add_and_square --args 3,4 --iter 500
    transd-cli apk game.apk
    transd-cli apk game.apk --run --func JNI_OnLoad
"#,
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => {
            print_usage();
        }
        "version" | "--version" | "-V" => {
            println!("transd-cli {}", env!("CARGO_PKG_VERSION"));
        }
        "info" => {
            if args.len() < 3 {
                eprintln!("Error: missing file path for 'info' command");
                eprintln!("Usage: transd-cli info <file.so>");
                process::exit(1);
            }
            let file_path = &args[2];
            match fs::read(file_path) {
                Ok(data) => {
                    if let Err(e) = info::print_elf_info(file_path, &data) {
                        eprintln!("ELF Inspector Error: {}", e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error reading file '{}': {}", file_path, e);
                    process::exit(1);
                }
            }
        }
        "run" => {
            if args.len() < 3 {
                eprintln!("Error: missing file path for 'run' command");
                eprintln!("Usage: transd-cli run <file.so> [--func <name>] [--args 1,2,3]");
                process::exit(1);
            }
            let file_path = &args[2];

            let mut target_func = None;
            let mut parsed_args = Vec::new();

            let mut idx = 3;
            while idx < args.len() {
                match args[idx].as_str() {
                    "--func" => {
                        if idx + 1 < args.len() {
                            target_func = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --func requires an argument");
                            process::exit(1);
                        }
                    }
                    "--args" => {
                        if idx + 1 < args.len() {
                            let arg_strs = args[idx + 1].split(',');
                            for s in arg_strs {
                                match s.trim().parse::<u32>() {
                                    Ok(v) => parsed_args.push(v),
                                    Err(_) => {
                                        // Try hex format 0x...
                                        if let Some(hex_str) = s.trim().strip_prefix("0x") {
                                            if let Ok(v) = u32::from_str_radix(hex_str, 16) {
                                                parsed_args.push(v);
                                                continue;
                                            }
                                        }
                                        eprintln!("Error: invalid argument '{}'", s);
                                        process::exit(1);
                                    }
                                }
                            }
                            idx += 2;
                        } else {
                            eprintln!("Error: --args requires an argument");
                            process::exit(1);
                        }
                    }
                    unknown => {
                        eprintln!("Error: unknown option '{}'", unknown);
                        print_usage();
                        process::exit(1);
                    }
                }
            }

            match fs::read(file_path) {
                Ok(data) => {
                    match runner::execute_so(file_path, &data, target_func, &parsed_args) {
                        Ok(code) => {
                            process::exit(code as i32);
                        }
                        Err(e) => {
                            eprintln!("Execution Error: {}", e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading file '{}': {}", file_path, e);
                    process::exit(1);
                }
            }
        }
        "apk" => {
            if args.len() < 3 {
                eprintln!("Error: missing file path for 'apk' command");
                eprintln!("Usage: transd-cli apk <file.apk> [--run] [--lib <name.so>] [--func <name>]");
                process::exit(1);
            }
            let file_path = &args[2];

            let mut run_app = false;
            let mut target_lib = None;
            let mut target_func = None;
            let mut parsed_args = Vec::new();

            let mut idx = 3;
            while idx < args.len() {
                match args[idx].as_str() {
                    "--run" => {
                        run_app = true;
                        idx += 1;
                    }
                    "--lib" => {
                        if idx + 1 < args.len() {
                            target_lib = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --lib requires an argument");
                            process::exit(1);
                        }
                    }
                    "--func" => {
                        if idx + 1 < args.len() {
                            target_func = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --func requires an argument");
                            process::exit(1);
                        }
                    }
                    "--args" => {
                        if idx + 1 < args.len() {
                            let arg_strs = args[idx + 1].split(',');
                            for s in arg_strs {
                                match s.trim().parse::<u32>() {
                                    Ok(v) => parsed_args.push(v),
                                    Err(_) => {
                                        if let Some(hex_str) = s.trim().strip_prefix("0x") {
                                            if let Ok(v) = u32::from_str_radix(hex_str, 16) {
                                                parsed_args.push(v);
                                                continue;
                                            }
                                        }
                                        eprintln!("Error: invalid argument '{}'", s);
                                        process::exit(1);
                                    }
                                }
                            }
                            idx += 2;
                        } else {
                            eprintln!("Error: --args requires an argument");
                            process::exit(1);
                        }
                    }
                    unknown => {
                        eprintln!("Error: unknown option '{}'", unknown);
                        print_usage();
                        process::exit(1);
                    }
                }
            }

            match fs::read(file_path) {
                Ok(data) => {
                    match apk_cmd::handle_apk_command(
                        file_path,
                        &data,
                        run_app,
                        target_lib,
                        target_func,
                        &parsed_args,
                    ) {
                        Ok(code) => {
                            process::exit(code as i32);
                        }
                        Err(e) => {
                            eprintln!("APK Error: {}", e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading file '{}': {}", file_path, e);
                    process::exit(1);
                }
            }
        }
        "devices" => {
            adb::check_adb_devices();
        }
        "bench" => {
            if args.len() < 3 {
                eprintln!("Error: missing file path for 'bench' command");
                eprintln!("Usage: transd-cli bench <file.so> [--func <name>] [--args 1,2,3] [--iter <count>]");
                process::exit(1);
            }
            let file_path = &args[2];
            let mut target_func = None;
            let mut parsed_args = Vec::new();
            let mut iterations = 100u32;

            let mut idx = 3;
            while idx < args.len() {
                match args[idx].as_str() {
                    "--func" => {
                        if idx + 1 < args.len() {
                            target_func = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --func requires an argument");
                            process::exit(1);
                        }
                    }
                    "--iter" => {
                        if idx + 1 < args.len() {
                            if let Ok(it) = args[idx + 1].parse::<u32>() {
                                iterations = it;
                            } else {
                                eprintln!("Error: invalid iteration count '{}'", args[idx + 1]);
                                process::exit(1);
                            }
                            idx += 2;
                        } else {
                            eprintln!("Error: --iter requires an argument");
                            process::exit(1);
                        }
                    }
                    "--args" => {
                        if idx + 1 < args.len() {
                            let arg_strs: Vec<&str> = args[idx + 1].split(',').collect();
                            for s in arg_strs {
                                match s.trim().parse::<u32>() {
                                    Ok(v) => parsed_args.push(v),
                                    Err(_) => {
                                        if let Some(hex_str) = s.trim().strip_prefix("0x") {
                                            if let Ok(v) = u32::from_str_radix(hex_str, 16) {
                                                parsed_args.push(v);
                                                continue;
                                            }
                                        }
                                        eprintln!("Error: invalid argument '{}'", s);
                                        process::exit(1);
                                    }
                                }
                            }
                            idx += 2;
                        } else {
                            eprintln!("Error: --args requires an argument");
                            process::exit(1);
                        }
                    }
                    unknown => {
                        eprintln!("Error: unknown option '{}'", unknown);
                        print_usage();
                        process::exit(1);
                    }
                }
            }

            match fs::read(file_path) {
                Ok(data) => {
                    match bench::run_benchmark(file_path, &data, target_func, &parsed_args, iterations) {
                        Ok(_) => {
                            process::exit(0);
                        }
                        Err(e) => {
                            eprintln!("Benchmark Error: {}", e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading file '{}': {}", file_path, e);
                    process::exit(1);
                }
            }
        }
        "package" => {
            if args.len() < 3 {
                eprintln!("Error: missing file path for 'package' command");
                eprintln!("Usage: transd-cli package <file.apk> [-o output.apk] [--bridge libtransd.so] [--primary-lib name.so] [--align 4096]");
                process::exit(1);
            }
            let input_path = &args[2];
            let mut output_path = None;
            let mut bridge_path = None;
            let mut primary_lib = None;
            let mut align = None;
            let mut config_props = Vec::new();

            let mut idx = 3;
            while idx < args.len() {
                match args[idx].as_str() {
                    "-o" | "--output" => {
                        if idx + 1 < args.len() {
                            output_path = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: -o/--output requires an argument");
                            process::exit(1);
                        }
                    }
                    "--bridge" => {
                        if idx + 1 < args.len() {
                            bridge_path = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --bridge requires an argument");
                            process::exit(1);
                        }
                    }
                    "--primary-lib" => {
                        if idx + 1 < args.len() {
                            primary_lib = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --primary-lib requires an argument");
                            process::exit(1);
                        }
                    }
                    "--align" => {
                        if idx + 1 < args.len() {
                            if let Ok(val) = args[idx + 1].parse::<usize>() {
                                align = Some(val);
                            } else {
                                eprintln!("Error: invalid alignment value '{}'", args[idx + 1]);
                                process::exit(1);
                            }
                            idx += 2;
                        } else {
                            eprintln!("Error: --align requires an argument");
                            process::exit(1);
                        }
                    }
                    "--config" => {
                        if idx + 1 < args.len() {
                            let kv = &args[idx + 1];
                            if let Some((k, v)) = kv.split_once('=') {
                                config_props.push((k.to_string(), v.to_string()));
                            } else {
                                eprintln!("Error: --config requires key=value format");
                                process::exit(1);
                            }
                            idx += 2;
                        } else {
                            eprintln!("Error: --config requires an argument");
                            process::exit(1);
                        }
                    }
                    unknown => {
                        eprintln!("Error: unknown option '{}'", unknown);
                        print_usage();
                        process::exit(1);
                    }
                }
            }

            if let Err(e) = package::handle_package_command(
                input_path,
                output_path,
                bridge_path,
                primary_lib,
                align,
                &config_props,
            ) {
                eprintln!("Repackage Error: {}", e);
                process::exit(1);
            }
        }
        "test-device" => {
            let mut device_id = None;
            let mut apk_path = None;

            let mut idx = 2;
            while idx < args.len() {
                match args[idx].as_str() {
                    "-s" | "--device" => {
                        if idx + 1 < args.len() {
                            device_id = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: -s/--device requires an argument");
                            process::exit(1);
                        }
                    }
                    "--apk" => {
                        if idx + 1 < args.len() {
                            apk_path = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --apk requires an argument");
                            process::exit(1);
                        }
                    }
                    unknown => {
                        eprintln!("Error: unknown option '{}'", unknown);
                        print_usage();
                        process::exit(1);
                    }
                }
            }

            if let Err(e) = adb::test_device(device_id, apk_path) {
                eprintln!("ADB Test Error: {}", e);
                process::exit(1);
            }
        }
        "install" => {
            if args.len() < 3 {
                eprintln!("Error: missing APK file path for 'install' command");
                eprintln!("Usage: transd-cli install <file.apk> [-s <device>]");
                process::exit(1);
            }
            let apk_path = &args[2];
            let mut device_id = None;

            let mut idx = 3;
            while idx < args.len() {
                match args[idx].as_str() {
                    "-s" | "--device" => {
                        if idx + 1 < args.len() {
                            device_id = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: -s/--device requires an argument");
                            process::exit(1);
                        }
                    }
                    unknown => {
                        eprintln!("Error: unknown option '{}'", unknown);
                        print_usage();
                        process::exit(1);
                    }
                }
            }

            if let Err(e) = adb::install_apk(device_id, apk_path) {
                eprintln!("ADB Install Error: {}", e);
                process::exit(1);
            }
        }
        "launch" => {
            if args.len() < 3 {
                eprintln!("Error: missing target package or APK for 'launch' command");
                eprintln!("Usage: transd-cli launch <package_or_apk> [--activity <act>] [-s <device>]");
                process::exit(1);
            }
            let target = &args[2];
            let mut device_id = None;
            let mut activity = None;

            let mut idx = 3;
            while idx < args.len() {
                match args[idx].as_str() {
                    "-s" | "--device" => {
                        if idx + 1 < args.len() {
                            device_id = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: -s/--device requires an argument");
                            process::exit(1);
                        }
                    }
                    "-a" | "--activity" => {
                        if idx + 1 < args.len() {
                            activity = Some(args[idx + 1].as_str());
                            idx += 2;
                        } else {
                            eprintln!("Error: --activity requires an argument");
                            process::exit(1);
                        }
                    }
                    unknown => {
                        eprintln!("Error: unknown option '{}'", unknown);
                        print_usage();
                        process::exit(1);
                    }
                }
            }

            if let Err(e) = adb::launch_app(device_id, target, activity) {
                eprintln!("ADB Launch Error: {}", e);
                process::exit(1);
            }
        }
        unknown => {
            eprintln!("Error: unknown command '{}'", unknown);
            print_usage();
            process::exit(1);
        }
    }
}
