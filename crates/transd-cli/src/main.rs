mod adb;
mod apk_cmd;
mod info;
mod runner;

use std::env;
use std::fs;
use std::process;

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

    help
        Print this help message

EXAMPLES:
    transd-cli info libnative.so
    transd-cli run libcalc.so --func add_and_square --args 3,4
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
        unknown => {
            eprintln!("Error: unknown command '{}'", unknown);
            print_usage();
            process::exit(1);
        }
    }
}
