#include <iostream>  
#include <set>  
#include <string>  
#include <sstream>  
  
using namespace std;  
  
struct A  
{  
    int age;  
    string name;
    bool operator<(const A& a);
	//{
	//	return age < a.age;
	//}
};  

bool A::operator<(const A& a){
	return this.age < a.age;
}
  
/*bool operator<(const A &a, const A &b)  
{  
    return a.age < b.age;  
} 
*/ 
  
int main(int argc, char* argv[])  
{  
    set<A> setA;  
    stringstream ss;  
    for (int i = 0; i < 10; i++)  
    {  
        ss.clear();  
        ss.str("");  
        ss << "test" << i;  
        A a;  
        a.age = i;  
        a.name = ss.str();  
        setA.insert(a);  
    }  
  
    for (set<A>::iterator it = setA.begin(); it != setA.end(); it++)  
    {  
        A a = (A)(*it);  
        printf("age = %d, name = %s \n", a.age, a.name.c_str());  
    }  
    getchar();  
    return 0;  
}  
