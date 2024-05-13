#include <iostream>
#include <boost/program_options.hpp>
#include <boost/program_options/cmdline.hpp>

using namespace boost::program_options;
using boost::program_options::detail::cmdline;
using namespace command_line_style;


void static inline splitInputCmd(const std::string& input, std::vector<std::string>& splitedList)
{
	std::string tmp="";
	for( size_t i=0; i<input.size(); i++)
	{
		char c = input[i];
		if( c == ' ' )
		{
			if(!tmp.empty())
				splitedList.push_back(tmp);
			tmp="";
		}
		else if(c == '\'' )
		{
			i++;
			while( input[i] != '\'' )
			{ tmp+=input[i]; i++; }
		}
		else
		{
			tmp+=c;
		}
	}

	if(!tmp.empty())
		splitedList.push_back(tmp);
}


int testCmdLineSplit()
{
    std::string domain;
    std::string user;
    std::string password;
    std::string cmdLine;

    options_description desc("Allowed options");
    desc.add_options()
    ("help,h", "print usage message")
    ("user,u", value(&user), "pathname for output")
    ("domain,d", value(&domain), "pathname for output")
    ("password,p", value(&password), "pathname for output")
    ("cmdLine,c", value(&cmdLine), "pathname for output")
    ;

    positional_options_description p;
    p.add("module", 0);

    cmdline::style_t style = cmdline::style_t(allow_long | long_allow_adjacent);

    std::string test = "binary -u tester -d doamin -p password -c \"hoho gogo toto\"";

    std::vector<std::string> splitedCmd;
	splitInputCmd(test, splitedCmd);


    cmdline cmd(splitedCmd);
    // cmd.style(style);
    cmd.set_options_description(desc);
    cmd.allow_unregistered();
    // cmd.set_positional_options(p);

    std::vector<option> options = cmd.run();

    std::string result;
    for(unsigned j = 0; j < options.size(); ++j)
    {
        option opt = options[j];

        std::cout << opt.string_key << " " << opt.value.size() << " " << opt.value[0] << std::endl;
    }

    return 0;
}


int main()
{
    testCmdLineSplit();

    return 0;
}