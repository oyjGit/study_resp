#ifndef __SINGLETON_H__
#define __SINGLETON_H__

#include <mutex>

template <typename T>
class CSingleton
{
private:
	static std::once_flag mFlag;
	static T* mInstance;

	CSingleton(const CSingleton& src) = delete;
	CSingleton &operator=(const CSingleton& src) = delete;

protected:
	CSingleton() {}
	~CSingleton() { destroyInstance(); }

public:
	static T* getInstance()
	{
		std::call_once(mFlag, []() { mInstance = new T(); });
		return mInstance;
	}

	static void destroyInstance()
	{
		if (nullptr != mInstance) 
		{
			delete mInstance;
			mInstance = nullptr;
		}
	}
};

template<class T>
std::once_flag CSingleton<T>::mFlag;

template<class T>
T* CSingleton<T>::mInstance = nullptr;

#endif
