#include <gtest/gtest.h>
#include <utility>
#include "../lib/gwatch.h"

class DebuggerTests : public testing::Test {
private:
    std::vector<char*> vdup(std::vector<std::string>& base) {
        std::vector<char*> res;
        for (std::string& s : base) {
            res.push_back(const_cast<char*>(s.c_str()));
        }
        return res;
    }

protected:
    std::string exec_path = "bin/test_file";

    std::vector<std::string> argv_missing_var { "-v", "--exec", exec_path, "--", "ugabuga"};
    std::vector<std::string> argv_missing_exec { "--var", "x4", "-e", "--", "ugabuga"};
    std::vector<std::string> argv_missing_test_param { "--var", "x4", "--exec", exec_path};
    std::vector<std::string> argv_valid_4 { "--var", "xd4", "--exec", exec_path, "--", "ugabuga"};
    std::vector<std::string> argv_valid_8 { "--var", "xd8", "--exec", exec_path, "--", "ugabuga"};
    std::vector<std::string> argv_valid_unused { "--var", "xd_unused", "--exec", exec_path, "--", "ugabuga"};

    std::vector<char*> argv_missing_var_c;
    std::vector<char*> argv_missing_exec_c;
    std::vector<char*> argv_missing_test_param_c;
    std::vector<char*> argv_valid_4_c;
    std::vector<char*> argv_valid_8_c;
    std::vector<char*> argv_valid_unused_c;

    std::vector<std::string> output_files {"argv_valid_4_output.txt", "argv_valid_8_output.txt",
                                            "argv_valid_unused_output.txt"};
    std::vector<std::string> expected_output_files {"../expected/argv_valid_4_expected.txt", "../expected/argv_valid_8_expected.txt",
                                                    "../expected/argv_valid_unused_expected.txt"};


    DebuggerTests() {
        argv_missing_var_c = vdup(argv_missing_var);
        argv_missing_exec_c = vdup(argv_missing_exec);
        argv_missing_test_param_c = vdup(argv_missing_test_param);
        argv_valid_4_c = vdup(argv_valid_4);
        argv_valid_8_c = vdup(argv_valid_8);
        argv_valid_unused_c = vdup(argv_valid_unused);
    }
};

TEST_F(DebuggerTests, test_symbol_finding) {
    std::pair<int64_t, int8_t> xd4 = get_variable_virt_addr_and_size(exec_path, "xd4");
    EXPECT_GT(xd4.first, 0);
    EXPECT_GT(xd4.second, 0);
    std::pair<int64_t, int8_t> xd8 = get_variable_virt_addr_and_size(exec_path, "xd8");
    EXPECT_GT(xd8.first, 0);
    EXPECT_GT(xd8.second, 0);
    std::pair<int64_t, int8_t> xd16 = get_variable_virt_addr_and_size(exec_path, "xd16");
    EXPECT_EQ(xd16.first, -1);
    EXPECT_EQ(xd16.second, -1);
}

TEST_F(DebuggerTests, test_nonzero_exit) {
    EXPECT_EQ(gwatch_main(argv_missing_var_c.size(), argv_missing_var_c.data()), 1);
    EXPECT_EQ(gwatch_main(argv_missing_exec_c.size(), argv_missing_exec_c.data()), 1);
    EXPECT_EQ(gwatch_main(argv_missing_test_param_c.size(), argv_missing_test_param_c.data()), 1);
}

class CoutRedirect {
private:
    std::ofstream output_file;
    std::streambuf* old_buf;

public:
    CoutRedirect(std::string filename) : output_file(filename) {
        old_buf = std::cout.rdbuf(output_file.rdbuf());
    }

    ~CoutRedirect() {
        std::cout.rdbuf(old_buf);
        output_file.close();
    }
};

TEST_F(DebuggerTests, test_zero_exit) {
    {
        CoutRedirect cr ("argv_valid_4_output.txt");
        EXPECT_EQ(gwatch_main(argv_valid_4_c.size(), argv_valid_4_c.data()), 0);
    }
    {
        CoutRedirect cr ("argv_valid_8_output.txt");
        EXPECT_EQ(gwatch_main(argv_valid_8_c.size(), argv_valid_8_c.data()), 0);
    }
    {
        CoutRedirect cr ("argv_valid_unused_output.txt");
        EXPECT_EQ(gwatch_main(argv_valid_unused_c.size(), argv_valid_unused_c.data()), 0);
    }
}

TEST_F(DebuggerTests, test_validity_of_outputs) {
    bool failed = false;
    for (auto i = 0; i < expected_output_files.size(); ++i) {
        std::ifstream output(output_files[i], std::ifstream::binary|std::ifstream::ate);
        std::ifstream expected(expected_output_files[i], std::ifstream::binary|std::ifstream::ate);

        if (output.fail() || expected.fail()) {
            failed = true;
            break;
        }

        output.seekg(0, std::ifstream::beg);
        expected.seekg(0, std::ifstream::beg);

        if (!std::equal(std::istreambuf_iterator<char>(expected.rdbuf()),
                    std::istreambuf_iterator<char>(),
                    std::istreambuf_iterator<char>(output.rdbuf()))) {
            failed = true;
            break;
        }
    }

    for (auto iter = output_files.begin(); iter != output_files.end(); ++iter) {
       std::remove((*iter).c_str());
    }
    if (failed) FAIL();
}