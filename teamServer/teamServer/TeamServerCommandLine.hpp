#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace TeamServerCommandLine
{
inline bool splitInput(const std::string& input, std::vector<std::string>& tokens)
{
    tokens.clear();
    std::string token;
    for (std::size_t i = 0; i < input.size(); ++i)
    {
        const char c = input[i];
        if (c == ' ')
        {
            if (!token.empty())
                tokens.push_back(token);
            token.clear();
        }
        else if (c == '\'')
        {
            const std::size_t closingQuote = input.find('\'', i + 1);
            if (closingQuote == std::string::npos)
            {
                tokens.clear();
                return false;
            }
            token.append(input, i + 1, closingQuote - i - 1);
            i = closingQuote;
        }
        else
        {
            token += c;
        }
    }

    if (!token.empty())
        tokens.push_back(token);
    return true;
}
} // namespace TeamServerCommandLine
