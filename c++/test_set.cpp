#include <set>
#include <iostream>
#include <string>

using namespace std;

class test{

public:
	test(int i, int j):a(i), b(j){}
	~test(){}
	int a;
	int b;
	void p() const {cout<<"a="<<a<<endl;}
	bool operator<(const test& t) const {return b<t.b;}

};

int main()
{
	set<int> si;
	int ret = 0;
	int count = 0;
	si.insert(1);
	si.insert(2);
	si.insert(1);
	for(auto i=si.begin();i!=si.end();i++){
		cout<<"count="<<count++<<","<<(*i)<<endl;
	}
	count = 0;
	set<test> st;
	test t1(1,1);
	test t2(2,2);
	test t3(1,3);
	st.insert(t1);
	st.insert(t2);
	st.insert(t3);
	for(auto i=st.begin();i!=st.end();i++){
		cout<<"count="<<count++<<endl;
		(*i).p();
	}
	return 0;	
}
