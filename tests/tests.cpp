#define BOOST_TEST_NO_MAIN 
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#include <boost/test/output_test_stream.hpp>
using boost::test_tools::output_test_stream;

#include <iostream>
#include "../src/vkey.hpp"

using namespace std;
using namespace VKey;
using namespace boost;

BOOST_AUTO_TEST_SUITE(VKeyTests)

BOOST_AUTO_TEST_CASE(Sqlite3Test)
{
	BOOST_CHECK_EQUAL(1,1);
}

BOOST_AUTO_TEST_SUITE_END()
