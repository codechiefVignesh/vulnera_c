// CS22B2004
// VIGNESH ARAVINDH B

/*
NOTE :: please change the *FOLDER* name below in the main function that contains the testing sample code.
The code iteratively parses through each file and displays the vulnerabilities.
*/




#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <set>
#include <unordered_map>
#include <filesystem> 

namespace fs = std::filesystem;

class Parser 
{
    public:
        void parseFolder(const std::string &folderPath); // Parse all files in a folder
        void parseFile(const std::string &filename); // Parse a single file

    private:
        void checkArithmeticOperation(const std::string &line, int lineNumber);
        void checkCastingOperations(const std::string &line, int lineNumber);
        void checkStringLengthAssignment(const std::string &line, int lineNumber);
        void checkVariableDeclarations(const std::string &line, int lineNumber);
        void checkComparisonOperations(const std::string &line, int lineNumber);
        
        std::set<std::string> issuedWarnings; // To avoid duplicate warnings
        std::unordered_map<std::string, std::string> variableTypes; // Store variable types

        void addVariableType(const std::string &name, const std::string &type);
};

void Parser::parseFolder(const std::string &folderPath) 
{
    for (const auto &entry : fs::directory_iterator(folderPath)) 
    {
        if (entry.is_regular_file() && entry.path().extension() == ".cpp") 
        {
            std::cout << "Parsing file: " << entry.path().filename() << std::endl;
            parseFile(entry.path().string());
            std::cout << std::endl; // Separate output for different files
        }
    }
}

void Parser::parseFile(const std::string &filename) 
{
    std::ifstream file(filename);
    std::string line;
    int lineNumber = 0;

    while (std::getline(file, line)) 
    {
        lineNumber++;
        checkVariableDeclarations(line, lineNumber);
        checkArithmeticOperation(line, lineNumber);
        checkCastingOperations(line, lineNumber);
        checkStringLengthAssignment(line, lineNumber);
        checkComparisonOperations(line, lineNumber); // Check comparisons
    }
}

void Parser::checkVariableDeclarations(const std::string &line, int lineNumber) 
{
    std::regex varDeclPattern(R"((unsigned\s+short|unsigned\s+int|int|long|unsigned\s+long|float|double)\s+(\w+)\s*=\s*([^;]+);)");
    std::smatch match;

    if (std::regex_search(line, match, varDeclPattern)) 
    {
        std::string type = match[1].str();
        std::string variableName = match[2].str();
        std::string value = match[3].str();
        
        addVariableType(variableName, type);
    }
}

void Parser::addVariableType(const std::string &name, const std::string &type) 
{
    variableTypes[name] = type;
}

void Parser::checkArithmeticOperation(const std::string &line, int lineNumber) 
{
    std::regex arithmeticOpPattern(R"((\w+)\s*([+\-*/])\s*(\w+))");
    std::smatch match;

    if (std::regex_search(line, match, arithmeticOpPattern)) 
    {
        std::string variable1 = match[1].str();
        std::string operatorSymbol = match[2].str();
        std::string variable2 = match[3].str();

        std::string type1 = variableTypes[variable1];
        std::string type2 = variableTypes[variable2];

        if ((type1 == "unsigned long" || type2 == "unsigned long") ||
            (type1 == "unsigned short" && type2 == "unsigned short") ||
            (type1 == "unsigned int" && type2 == "unsigned int") ||
            (type1 == "long" && type2 == "long") ||
            (type1 == "float" && type2 == "float") ||
            (type1 == "double" && type2 == "double") ||
            (type1 == "int" && type2 == "unsigned int") ||
            (type1 == "unsigned int" && type2 == "int") ||
            (type1 == "int" && type2 == "unsigned short") ||
            (type1 == "unsigned short" && type2 == "int")) {
            std::cout << "Warning (line " << lineNumber << "): Potential implicit casting issues between types: "
                      << type1 << " and " << type2 << " in operation '" << variable1 << " " << operatorSymbol << " " << variable2 << "'" << std::endl;
        }

        if (issuedWarnings.insert("Potential overflow due to '" + variable1 + " " + operatorSymbol + " " + variable2 + "'").second) {
            std::cout << "Warning (line " << lineNumber << "): Potential overflow due to '" 
                      << variable1 << " " << operatorSymbol << " " << variable2 << "'" << std::endl;
        }
    }
}

void Parser::checkCastingOperations(const std::string &line, int lineNumber) 
{
    std::regex castPattern(R"((\w+)\s*=\s*static_cast<(\w+)>\s*\((\w+)\))");
    std::smatch match;

    if (std::regex_search(line, match, castPattern)) 
    {
        std::string variable = match[1].str();
        std::string targetType = match[2].str();
        std::string sourceVariable = match[3].str();
        std::string sourceType = variableTypes[sourceVariable];

        if (targetType == "int" && sourceType == "unsigned short") {
            std::cout << "Warning (line " << lineNumber << "): Potential loss of data when casting from '"
                      << sourceType << "' to '" << targetType << "' for variable '" << variable << "'" << std::endl;
        }
    }
}

void Parser::checkStringLengthAssignment(const std::string &line, int lineNumber) 
{
    std::regex lengthPattern(R"((\w+)\s*=\s*strlen\((\w+)\))");
    std::smatch match;

    if (std::regex_search(line, match, lengthPattern)) 
    {
        std::string variable = match[1].str();
        std::string stringVariable = match[2].str();

        if (issuedWarnings.insert("Warning due to assignment of 'size_t' to signed 'int'").second) {
            std::cout << "Warning (line " << lineNumber << "): Potential issue when assigning 'size_t' from strlen() to signed variable '"
                      << variable << "'" << std::endl;
        }
    }
}

void Parser::checkComparisonOperations(const std::string &line, int lineNumber) 
{
    std::regex comparisonOpPattern(R"((\w+)\s*([<>=!]=?)\s*(\w+))");
    std::smatch match;

    if (std::regex_search(line, match, comparisonOpPattern)) 
    {
        std::string variable1 = match[1].str();
        std::string operatorSymbol = match[2].str();
        std::string variable2 = match[3].str();

        std::string type1 = variableTypes[variable1];
        std::string type2 = variableTypes[variable2];

        if ((type1 == "unsigned short" && type2 == "int") || 
            (type1 == "int" && type2 == "unsigned short") ||
            (type1 == "unsigned int" && type2 == "int") || 
            (type1 == "int" && type2 == "unsigned int") ||
            (type1 == "unsigned long" && type2 == "long") ||
            (type1 == "long" && type2 == "unsigned long") ||
            (type1 == "float" && type2 == "double") ||
            (type1 == "double" && type2 == "float")) {
            if (issuedWarnings.insert("Warning: Potential issues with comparison between '" + type1 + "' and '" + type2 + "'").second) {
                std::cout << "Warning (line " << lineNumber << "): Potential issues with comparison '" 
                          << variable1 << " " << operatorSymbol << " " << variable2 << "'" << std::endl;
            }
        }
    }
}

int main() 
{
    Parser parser;
    std::string folderPath = "./cpp_files"; 
    parser.parseFolder(folderPath);
    return 0;
}
