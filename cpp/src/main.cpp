#include "analysis.h"
#include <fstream>
#include <iostream>

static void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name
              << " [--installer PATH] [--procmon PATH] [--procdump PATH]"
                 " [--output PATH] [--verbose]\n";
}

static Options parse_args(int argc, char* argv[]) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&](const std::string& option_name) -> std::string {
            if (i + 1 >= argc)
                throw std::runtime_error(option_name + " requires a value");
            return argv[++i];
        };

        if      (arg == "--installer") options.installer = fs::path(require_value(arg));
        else if (arg == "--procmon")   options.procmon   = fs::path(require_value(arg));
        else if (arg == "--procdump")  options.procdump  = fs::path(require_value(arg));
        else if (arg == "--output")    options.output    = fs::path(require_value(arg));
        else if (arg == "--verbose")   options.verbose   = true;
        else if (arg == "--help" || arg == "-h") { print_usage(argv[0]); std::exit(0); }
        else throw std::runtime_error("Unknown argument: " + arg);
    }

    if (!options.installer && !options.procmon && !options.procdump)
        throw std::runtime_error("Provide at least one of --installer, --procmon, or --procdump");

    return options;
}

int main(int argc, char* argv[]) {
    try {
        const Options options = parse_args(argc, argv);
        const ForensicsToolkitCpp toolkit(options);
        const AnalysisReport report = toolkit.run_analysis();

        std::ofstream output(options.output);
        if (!output)
            throw std::runtime_error("Unable to write output report: " + options.output.string());
        output << to_json(report);

        std::cout << "Analyse voltooid: " << options.output << "\n";
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "error: " << exc.what() << "\n";
        print_usage(argv[0]);
        return 2;
    }
}
