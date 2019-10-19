// Copyright (c) Microsoft Corporation
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "pch.h"
#include "httpcall.h"
#include "../Mock/lhc_mock.h"

namespace
{

// This code provides 2 class templates called AsyncRunnableBase and
// AsyncRunnableStatelessBase which help implment XAsync providers easily.
// The main goal of the design is to minimize the amount of boilerplate and edge
// cases each provider needs to implement.

// In both cases the client is supposed to define a class that derives from one
// of the 2 bases and provide at least Begin and DoWork methods (which are
// are called when servicing that specific XAsyncOp).

// XAsyncRunnableBase is the general purpose helper. It allocates an instance of
// the derived class and passes it down as the provider context, so the client
// can store arbitrary data (which can be passed to its constructor via
// MakeAndRun).
// The client can implement the following 4 provider operations as methods:
// - Begin
// - DoWork
// - GetResult (provided for clients returning void)
// - Cancel (optional)
// The destructor will be called in XAsyncOp::Cleanup to free resources.
// There are a number of protected methods that allow the client to schedule and
// complete the async operation (failure is always signalled by returning an
// error code from one of the provider methods)
template <class TDerived, class TResult>
class AsyncRunnableBase
{
public:
    // split to allow other memory management strategies?
    template<class... TArgs>
    static HRESULT MakeAndRun(
        _In_opt_ void* identity,
        _In_opt_z_ char const* identityName,
        _In_ XAsyncBlock* async,
        TArgs&&... args
    ) noexcept
    {
        try
        {
            auto self = std::make_unique<TDerived>(std::forward<TArgs>(args)...);
            HRESULT hr = XAsyncBegin(async, self.get(), identity, identityName, &AsyncRunnableBase::Provider);
            if (FAILED(hr))
            {
                return hr;
            }

            self.release();
            return S_OK;
        }
        catch (std::bad_alloc)
        {
            return E_OUTOFMEMORY;
        }
        catch (...) // needs good catch return setup
        {
            return E_FAIL;
        }
    }

protected:

    HRESULT MarkWaitingOnCallback() noexcept
    {
        assert(m_state == State::Polling);

        m_state = State::PendingCallback;
        return S_OK;
    }

    HRESULT ScheduleOnQueue() noexcept
    {
        return ScheduleOnQueueAfter({});
    }

    HRESULT ScheduleOnQueueAfter(std::chrono::milliseconds d) noexcept
    {
        assert(m_state == State::Polling);
        HRESULT hr = XAsyncSchedule(m_async, static_cast<uint32_t>(d.count()));
        if (FAILED(hr))
        {
            return hr;
        }

        m_state = State::PendingPoll;
        return S_OK;
    }

    HRESULT Succeed() noexcept
    {
        return SucceedWithResultSize(SizeOfHelper<TResult>::value);
    }

    HRESULT SucceedWithResultSize(size_t size) noexcept
    {
        assert(m_state == State::Polling || m_state == State::PendingCallback);

        m_state = State::Complete;
        XAsyncComplete(m_async, S_OK, size);

        return S_OK;
    }

    HRESULT Fail(HRESULT hr) noexcept
    {
        assert(FAILED(hr));
        assert(m_state == State::PendingCallback); // don't call Fail from DoWork, just return the failure instead

        m_state = State::Complete;
        XAsyncComplete(m_async, hr, 0);

        return S_OK;
    }

protected: // Default impls
    void GetResult(size_t, void*)
    {
        assert(false);
    }
    void Cancel() {}

private:
    using State = AsyncWrapper::State;

    static HRESULT Provider(XAsyncOp op, _In_ XAsyncProviderData const* data) noexcept
    {
        static_assert(std::is_base_of<AsyncRunnableBase<TDerived, TResult>, TDerived>::value,
            "TDerived must be the class deriving from AsyncRunnableBase");

        auto self = static_cast<AsyncRunnableBase*>(data->context);
        assert(self);
        self->m_async = data->async;

        switch (op)
        {
        case XAsyncOp::Begin:
            try
            {
                assert(self->m_state == State::Created);
                self->m_state = State::Polling;

                HRESULT hr = self->AsDerived()->Begin();
                if (FAILED(hr))
                {
                    self->m_state = State::Complete;
                    return hr;
                }

                if (self->m_state == State::Polling)
                {
                    assert(false);
                    self->m_state = State::Complete;
                    return E_FAIL;
                }

                return S_OK;
            }
            catch (...) // needs good catch return setup
            {
                self->m_state = State::Complete;
                return E_FAIL;
            }
        case XAsyncOp::DoWork:
            try
            {
                assert(self->m_state == State::PendingPoll);
                self->m_state = State::Polling;

                HRESULT hr = self->AsDerived()->DoWork();
                if (FAILED(hr))
                {
                    self->m_state = State::Complete;
                    XAsyncComplete(data->async, hr, 0);
                    return S_OK;
                }

                switch (self->m_state)
                {
                case AsyncWrapper::State::Created:
                    assert(false); // this cannot happen
                    return E_UNEXPECTED;
                case AsyncWrapper::State::Polling:
                    assert(false); // forgot to complete or schedule again
                    self->m_state = State::Complete;
                    XAsyncComplete(data->async, E_UNEXPECTED, 0);
                    return E_FAIL;
                case AsyncWrapper::State::PendingPoll:
                case AsyncWrapper::State::PendingCallback:
                    return E_PENDING;
                case AsyncWrapper::State::Complete:
                    return S_OK;
                }
            }
            catch (...) // needs good catch return setup
            {
                self->m_state = State::Complete;
                XAsyncComplete(data->async, E_FAIL, 0);
                return S_OK;
            }
        case XAsyncOp::GetResult:
            try
            {
                assert(self->m_state == State::Complete);
                self->AsDerived()->GetResult(data->bufferSize, static_cast<TResult*>(data->buffer));
                return S_OK;
            }
            catch (...) // needs good catch return setup
            {
                // this seems really bad, is get result allowed to fail?
                return E_UNEXPECTED;
            }
        case XAsyncOp::Cancel:
            try
            {
                self->AsDerived()->Cancel();
                return S_OK;
            }
            catch (...) // needs good catch return setup
            {
                // what to do here? let's assume the task will still complete normally
                assert(false);
                return S_OK;
            }
        case XAsyncOp::Cleanup:
            // cleanup most definitely should be no fail, die hard on exceptions
            {
                assert(self->m_state == State::Complete);

                // take ownership of self
                std::unique_ptr<TDerived>{ self->AsDerived() };
                return S_OK;
            }
        }

        // VS can't quite tell that we should always return early
        assert(false);
        return E_UNEXPECTED;
    }

    TDerived* AsDerived() noexcept
    {
        return static_cast<TDerived*>(this);
    }

    State m_state = State::Created;
    XAsyncBlock* m_async;
};

// Helper for AsyncRunnableStatelessBase
class AsyncWrapper
{
public:
    enum class State
    {
        Created,
        Polling,
        PendingPoll,
        PendingCallback,
        Complete,
    };

    AsyncWrapper(_In_ XAsyncBlock* async, size_t rsize, State s):
        m_async{ async }, m_resultSize{ rsize }, m_state{ s }
    {}

    HRESULT MarkWaitingOnCallback() noexcept
    {
        assert(m_state == State::Polling);

        m_state = State::PendingCallback;
        return S_OK;
    }

    HRESULT ScheduleOnQueue() noexcept
    {
        return ScheduleOnQueueAfter({});
    }

    HRESULT ScheduleOnQueueAfter(std::chrono::milliseconds d) noexcept
    {
        assert(m_state == State::Polling);
        HRESULT hr = XAsyncSchedule(m_async, static_cast<uint32_t>(d.count()));
        if (FAILED(hr))
        {
            return hr;
        }

        m_state = State::PendingPoll;
        return S_OK;
    }

    HRESULT Succeed() noexcept
    {
        return SucceedWithResultSize(m_resultSize);
    }

    HRESULT SucceedWithResultSize(size_t size) noexcept
    {
        assert(m_state == State::Polling);

        m_state = State::Complete;
        XAsyncComplete(m_async, S_OK, size);

        return S_OK;
    }

    State GetState() const noexcept
    {
        return m_state;
    }

    XAsyncBlock* GetRaw() const noexcept
    {
        return m_async;
    }

private:
    XAsyncBlock* const m_async; // non owning
    size_t const m_resultSize;
    State m_state;
};

template<class T>
struct SizeOfHelper
{
    static constexpr size_t value = sizeof(T);
};

template<>
struct SizeOfHelper<void>
{
    static constexpr size_t value = 0;
};

// AsyncRunnableStatelessBase is a specialized helper for building providers
// that do not own their context. Unlike AsyncRunnableBase it does not allocate
// at all, relying on the TContext* object to carry any information it needs.
// The client can implement the following 5 provider operations as static
// methods:
// - Begin
// - DoWork
// - GetResult (provided for clients returning void)
// - Cancel (optional)
// - Cleanup (optional)
// Each of these methods is passed a pointer to the context. Begin and DoWork
// are also given an AsyncWrapper object (by reference) which can be used to
// schedule or complete the operation (like AsyncRunnableBase, returning an
// error code will fail the operation).
template<class TDerived, class TContext, class TResult>
class AsyncRunnableStatelessBase
{
public:
    static HRESULT Run(
        _In_opt_ void* identity,
        _In_opt_z_ char const* identityName,
        _In_ XAsyncBlock* async,
        _In_ TContext* ctx
    ) noexcept
    {
        return XAsyncBegin(async, ctx, identity, identityName, &AsyncRunnableStatelessBase::Provider);
    }

protected:

protected: // default impls
    static void GetResult(TContext*, size_t, void*)
    {
        assert(false);
    }
    static void Cancel(TContext*) {}
    static void Cleanup(TContext*) {}

private:
    static HRESULT Provider(XAsyncOp op, _In_ XAsyncProviderData const* data) noexcept
    {
        static_assert(std::is_base_of<AsyncRunnableStatelessBase<TDerived, TContext, TResult>, TDerived>::value,
            "TDerived must be the class deriving from AsyncRunnableStatelessBase");

        auto ctx = static_cast<TContext*>(data->context);

        switch (op)
        {
        case XAsyncOp::Begin:
            try
            {
                AsyncWrapper aw{ data->async, SizeOfHelper<TResult>::value, AsyncWrapper::State::Polling };

                HRESULT hr = TDerived::Begin(ctx, aw);
                if (FAILED(hr))
                {
                    return hr;
                }

                if (aw.GetState() == AsyncWrapper::State::Polling)
                {
                    assert(false); // forgot to complete or schedule again
                    return E_UNEXPECTED;
                }

                return S_OK;
            }
            catch (...) // needs good catch return setup
            {
                return E_FAIL;
            }
        case XAsyncOp::DoWork:
            try
            {
                AsyncWrapper aw{ data->async, SizeOfHelper<TResult>::value, AsyncWrapper::State::Polling };

                HRESULT hr = TDerived::DoWork(ctx, aw);
                if (FAILED(hr))
                {
                    assert(hr != E_PENDING); // DoWork should never return E_PENDING
                    XAsyncComplete(data->async, hr, 0);
                    return S_OK;
                }

                switch (aw.GetState())
                {
                case AsyncWrapper::State::Created:
                    assert(false); // this cannot happen
                    return E_UNEXPECTED;
                case AsyncWrapper::State::Polling:
                    assert(false); // forgot to complete or schedule again
                    XAsyncComplete(data->async, E_UNEXPECTED, 0);
                    return S_OK;
                case AsyncWrapper::State::PendingPoll:
                case AsyncWrapper::State::PendingCallback:
                    return E_PENDING;
                case AsyncWrapper::State::Complete:
                    return S_OK;
                }
            }
            catch (...) // needs good catch return setup
            {
                XAsyncComplete(data->async, E_FAIL, 0);
                return S_OK;
            }
        case XAsyncOp::GetResult:
            try
            {
                TDerived::GetResult(ctx, data->bufferSize, static_cast<TResult*>(data->buffer));
                return S_OK;
            }
            catch (...) // needs good catch return setup
            {
                // this seems really bad, is get result allowed to fail?
                return E_FAIL;
            }
        case XAsyncOp::Cancel:
            try
            {
                TDerived::Cancel(ctx);
                return S_OK;
            }
            catch (...) // needs good catch return setup
            {
                // what to do here? let's assume the task will still complete normally
                assert(false);
                return S_OK;
            }
        case XAsyncOp::Cleanup:
            // cleanup most definitely should be no fail, die hard on exceptions
            {
                TDerived::Cleanup(ctx);
                return S_OK;
            }
        }

        // VS can't quite tell that we should always return early
        assert(false);
        return E_UNEXPECTED;
    }
};

}

using namespace xbox::httpclient;

const int MIN_DELAY_FOR_HTTP_INTERNAL_ERROR_IN_MS = 10000;
#if HC_UNITTEST_API
    const int MIN_HTTP_TIMEOUT_IN_MS = 0; // speed up unit tests
#else
    const int MIN_HTTP_TIMEOUT_IN_MS = 5000;
#endif
const double MAX_DELAY_TIME_IN_SEC = 60.0;
const int RETRY_AFTER_CAP_IN_SEC = 15;
#define RETRY_AFTER_HEADER ("Retry-After")

HC_CALL::~HC_CALL()
{
    HC_TRACE_VERBOSE(HTTPCLIENT, "HCCallHandle dtor");
}

STDAPI 
HCHttpCallCreate(
    _Out_ HCCallHandle* callHandle
    ) noexcept
try 
{
    if (callHandle == nullptr)
    {
        return E_INVALIDARG;
    }

    auto httpSingleton = get_http_singleton(true);
    if (nullptr == httpSingleton)
        return E_HC_NOT_INITIALISED;

    HC_CALL* call = new HC_CALL();

    call->retryAllowed = httpSingleton->m_retryAllowed;
    call->timeoutInSeconds = httpSingleton->m_timeoutInSeconds;
    call->timeoutWindowInSeconds = httpSingleton->m_timeoutWindowInSeconds;
    call->retryDelayInSeconds = httpSingleton->m_retryDelayInSeconds;
    call->retryIterationNumber = 0;
    call->id = ++httpSingleton->m_lastId;

    HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallCreate [ID %llu]", call->id);

    *callHandle = call;
    return S_OK;
}
CATCH_RETURN()

STDAPI_(HCCallHandle) HCHttpCallDuplicateHandle(
    _In_ HCCallHandle call
    ) noexcept
try
{
    if (call == nullptr)
    {
        return nullptr;
    }

    HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallDuplicateHandle [ID %llu]", static_cast<HC_CALL*>(call)->id);
    ++call->refCount;

    return call;
}
CATCH_RETURN_WITH(nullptr)

STDAPI 
HCHttpCallCloseHandle(
    _In_ HCCallHandle call
    ) noexcept
try 
{
    if (call == nullptr)
    {
        return E_INVALIDARG;
    }

    HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallCloseHandle [ID %llu]", call->id);
    int refCount = --call->refCount;
    if (refCount <= 0)
    {
        ASSERT(refCount == 0); // should only fire at 0
        delete call;
    }

    return S_OK;
}
CATCH_RETURN()

HRESULT perform_http_call(
    _In_ std::shared_ptr<http_singleton> httpSingleton,
    _In_ HCCallHandle call,
    _Inout_ XAsyncBlock* asyncBlock
    )
{
    class Runner : public AsyncRunnableStatelessBase<Runner, HC_CALL, void>
    {
    public:
        static HRESULT Begin(HCCallHandle call, AsyncWrapper& aw)
        {
            auto httpSingleton = get_http_singleton(false);
            if (nullptr == httpSingleton)
            {
                return E_HC_NOT_INITIALISED;
            }

            return aw.ScheduleOnQueueAfter(call->delayBeforeRetry);
        }

        static HRESULT DoWork(HCCallHandle call, AsyncWrapper& aw)
        {
            auto httpSingleton = get_http_singleton(false);
            if (nullptr == httpSingleton)
            {
                return E_HC_NOT_INITIALISED;
            }

            bool matchedMocks = false;

            matchedMocks = Mock_Internal_HCHttpCallPerformAsync(call);
            if (matchedMocks)
            {
                return aw.Succeed();
            }
            else // if there wasn't a matched mock, then real call
            {
                HttpPerformInfo const& info = httpSingleton->m_httpPerform;
                if (info.handler == nullptr)
                {
                    assert(false);
                    return E_UNEXPECTED;
                }

                info.handler(call, aw.GetRaw(), info.context, httpSingleton->m_performEnv.get());
                return aw.MarkWaitingOnCallback();
            }
        }
    };

    return Runner::Run(reinterpret_cast<void*>(perform_http_call), __FUNCTION__, asyncBlock, call);
}

void clear_http_call_response(_In_ HCCallHandle call)
{
    call->responseString.clear();
    call->responseBodyBytes.clear();
    call->responseHeaders.clear();
    call->statusCode = 0;
    call->networkErrorCode = S_OK;
    call->platformNetworkErrorCode = 0;
    call->task.reset();
}

std::chrono::seconds GetRetryAfterHeaderTime(_In_ HC_CALL* call)
{
    auto it = call->responseHeaders.find(RETRY_AFTER_HEADER);
    if (it != call->responseHeaders.end())
    {
        int value = 0;
        http_internal_stringstream ss(it->second);
        ss >> value;

        if (!ss.fail())
        {
            if (value > RETRY_AFTER_CAP_IN_SEC)
            {
                // Cap the Retry-After header so users won't be locked out of an endpoint 
                // for a long time the limit is hit near the end of a period
                value = RETRY_AFTER_CAP_IN_SEC;
            }

            return std::chrono::seconds(value);
        }
    }

    return std::chrono::seconds(0);
}

bool http_call_should_retry(
    _In_ HCCallHandle call,
    _In_ const chrono_clock_t::time_point& responseReceivedTime)
{
    if (!call->retryAllowed)
    {
        return false;
    }

    if (call->networkErrorCode == E_HC_NO_NETWORK)
    {
        return false;
    }

    auto httpStatus = call->statusCode;

    if (httpStatus == 408 || // Request Timeout
        httpStatus == 429 || // Too Many Requests 
        httpStatus == 500 || // Internal Error
        httpStatus == 502 || // Bad Gateway 
        httpStatus == 503 || // Service Unavailable
        httpStatus == 504 || // Gateway Timeout
        call->networkErrorCode != S_OK)
    {
        std::chrono::milliseconds retryAfter = GetRetryAfterHeaderTime(call);

        // Compute how much time left before hitting the TimeoutWindow setting
        std::chrono::milliseconds timeElapsedSinceFirstCall = std::chrono::duration_cast<std::chrono::milliseconds>(responseReceivedTime - call->firstRequestStartTime);

        uint32_t timeoutWindowInSeconds = 0;
        HCHttpCallRequestGetTimeoutWindow(call, &timeoutWindowInSeconds);
        std::chrono::seconds timeoutWindow = std::chrono::seconds(timeoutWindowInSeconds);
        std::chrono::milliseconds remainingTimeBeforeTimeout = timeoutWindow - timeElapsedSinceFirstCall;
        if (call->traceCall) { HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallPerformExecute [ID %llu] remainingTimeBeforeTimeout %lld ms", call->id, remainingTimeBeforeTimeout.count()); }

        // Based on the retry iteration, delay 2,4,8,16,etc seconds by default between retries
        // Jitter the response between the current and next delay based on system clock
        // Max wait time is 1 minute
        uint32_t retryDelayInSeconds = 0;
        HCHttpCallRequestGetRetryDelay(call, &retryDelayInSeconds);
        double secondsToWaitMin = std::pow(retryDelayInSeconds, call->retryIterationNumber);
        double secondsToWaitMax = std::pow(retryDelayInSeconds, call->retryIterationNumber + 1);
        double secondsToWaitDelta = secondsToWaitMax - secondsToWaitMin;
        double lerpScaler = (responseReceivedTime.time_since_epoch().count() % 10000) / 10000.0; // from 0 to 1 based on clock
#if HC_UNITTEST_API
        lerpScaler = 0; // make unit tests deterministic
#endif
        double secondsToWaitUncapped = secondsToWaitMin + secondsToWaitDelta * lerpScaler; // lerp between min & max wait
        double secondsToWait = std::min(secondsToWaitUncapped, MAX_DELAY_TIME_IN_SEC); // cap max wait to 1 min
        std::chrono::milliseconds waitTime = std::chrono::milliseconds(static_cast<int64_t>(secondsToWait * 1000.0));
        if (retryAfter.count() > 0)
        {
            // Use either the waitTime or Retry-After header, whichever is bigger
            call->delayBeforeRetry = std::chrono::milliseconds(std::max(waitTime.count(), retryAfter.count()));
        }
        else
        {
            call->delayBeforeRetry = waitTime;
        }
        if (call->traceCall) { HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallPerformExecute [ID %llu] delayBeforeRetry %lld ms", call->id, call->delayBeforeRetry.count()); }

        // Remember result if there was an error and there was a Retry-After header
        if (call->retryAfterCacheId != 0 &&
            retryAfter.count() > 0 &&
            httpStatus > 400)
        {
            auto retryAfterTime = retryAfter + responseReceivedTime;
            http_retry_after_api_state state(retryAfterTime, httpStatus);
            auto httpSingleton = get_http_singleton(false);
            if (httpSingleton)
            {
                httpSingleton->set_retry_state(call->retryAfterCacheId, state);
            }
        }

        if (httpStatus == 500) // Internal Error
        {
            // For 500 - Internal Error, wait at least 10 seconds before retrying.
            if (call->delayBeforeRetry.count() < MIN_DELAY_FOR_HTTP_INTERNAL_ERROR_IN_MS)
            {
                call->delayBeforeRetry = std::chrono::milliseconds(MIN_DELAY_FOR_HTTP_INTERNAL_ERROR_IN_MS);
            }
        }

        if (remainingTimeBeforeTimeout.count() <= MIN_HTTP_TIMEOUT_IN_MS) 
        {
            // Need at least 5 seconds to bother making a call
            return false;
        }

        if (remainingTimeBeforeTimeout < call->delayBeforeRetry + std::chrono::milliseconds(MIN_HTTP_TIMEOUT_IN_MS))
        {
            // Don't bother retrying when out of time
            return false;
        }

        return true;
    }

    return false;
}

bool should_fast_fail(
    _In_ http_retry_after_api_state apiState,
    _In_ HC_CALL* call,
    _In_ const chrono_clock_t::time_point& currentTime,
    _Out_ bool* clearState
    )
{
    *clearState = false;

    if (apiState.statusCode < 400)
    {
        return false;
    }

    std::chrono::milliseconds remainingTimeBeforeRetryAfterInMS = std::chrono::duration_cast<std::chrono::milliseconds>(apiState.retryAfterTime - currentTime);
    if (remainingTimeBeforeRetryAfterInMS.count() <= 0)
    {
        // Only clear the API cache when Retry-After time is up
        *clearState = true;
        return false;
    }

    std::chrono::seconds timeoutWindowInSeconds = std::chrono::seconds(call->timeoutWindowInSeconds);
    chrono_clock_t::time_point timeoutTime = call->firstRequestStartTime + timeoutWindowInSeconds;

    // If the Retry-After will happen first, just wait till Retry-After is done, and don't fast fail
    if (apiState.retryAfterTime < timeoutTime)
    {
        call->delayBeforeRetry = remainingTimeBeforeRetryAfterInMS;
        return false;
    }
    else
    {
        return true;
    }
}

STDAPI 
HCHttpCallPerformAsync(
    _In_ HCCallHandle call,
    _Inout_ XAsyncBlock* asyncBlock
    ) noexcept
try
{
    if (call == nullptr)
    {
        return E_INVALIDARG;
    }

    if (call->traceCall) { HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallPerform [ID %llu]", call->id); }
    call->performCalled = true;

    class Runner : public AsyncRunnableBase<Runner, void>
    {
    public:
        Runner(HCCallHandle call, XTaskQueueHandle queue) noexcept:
            m_call{ call }, m_queue{ queue }, m_nestedQueue{ nullptr }
        {
            assert(m_call);
            HCHttpCallDuplicateHandle(m_call);
        }

        ~Runner()
        {
            if (m_nestedQueue)
            {
                XTaskQueueCloseHandle(m_nestedQueue);
            }
            HCHttpCallCloseHandle(m_call);
        }

        HRESULT Begin()
        {
            return ScheduleOnQueue();
        }

        HRESULT DoWork()
        {
            auto httpSingleton = get_http_singleton(false);
            if (nullptr == httpSingleton)
            {
                // todo only fail the first time
                return E_HC_NOT_INITIALISED;
            }

            auto requestStartTime = chrono_clock_t::now();
            if (m_call->retryIterationNumber == 0)
            {
                m_call->firstRequestStartTime = requestStartTime;
            }
            m_call->retryIterationNumber++;
            if (m_call->traceCall)
            {
                HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallPerformExecute [ID %llu] Iteration %d", m_call->id, m_call->retryIterationNumber);
            }

            http_retry_after_api_state apiState = httpSingleton->get_retry_state(m_call->retryAfterCacheId);
            if (apiState.statusCode >= 400)
            {
                bool clearState = false;
                if (should_fast_fail(apiState, m_call, requestStartTime, &clearState))
                {
                    HCHttpCallResponseSetStatusCode(m_call, apiState.statusCode);
                    if (m_call->traceCall)
                    {
                        HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallPerformExecute [ID %llu] Fast fail %d", m_call->id, apiState.statusCode);
                    }
                    return Succeed();
                }

                if (clearState)
                {
                    httpSingleton->clear_retry_state(m_call->retryAfterCacheId);
                }
            }

            if (m_nestedQueue == nullptr && m_queue != nullptr)
            {
                XTaskQueuePortHandle workPort;
                XTaskQueueGetPort(m_queue, XTaskQueuePort::Work, &workPort);
                XTaskQueueCreateComposite(workPort, workPort, &m_nestedQueue);
            }

            auto nestedBlock = std::make_unique<XAsyncBlock>();
            nestedBlock->queue = m_nestedQueue;
            nestedBlock->context = this;

            nestedBlock->callback = [](XAsyncBlock* nestedAsyncBlockPtr)
            {
                std::unique_ptr<XAsyncBlock> nestedAsyncBlock{ nestedAsyncBlockPtr };
                Runner* self = static_cast<Runner*>(nestedAsyncBlock->context);
                self->InnerAsyncCallback();
            };

            HRESULT hr = perform_http_call(httpSingleton, m_call, nestedBlock.get());
            if (FAILED(hr))
            {
                return hr;
            }

            nestedBlock.release();
            return MarkWaitingOnCallback();
        }

        void InnerAsyncCallback() noexcept
        try
        {
            auto httpSingleton = get_http_singleton(false);
            if (nullptr == httpSingleton)
            {
                HC_TRACE_WARNING(HTTPCLIENT, "Http completed after HCCleanup was called. Aborting call.");
                return;
            }

            auto responseReceivedTime = chrono_clock_t::now();

            uint32_t timeoutWindowInSeconds = 0;
            HCHttpCallRequestGetTimeoutWindow(m_call, &timeoutWindowInSeconds);

            if (http_call_should_retry(m_call, responseReceivedTime))
            {
                if (m_call->traceCall)
                {
                    HC_TRACE_INFORMATION(HTTPCLIENT, "HCHttpCallPerformExecute [ID %llu] Retry after %lld ms", m_call->id, m_call->delayBeforeRetry.count());
                }
                std::lock_guard<std::recursive_mutex> lock(httpSingleton->m_callRoutedHandlersLock);
                for (const auto& pair : httpSingleton->m_callRoutedHandlers)
                {
                    pair.second.first(m_call, pair.second.second);
                }

                clear_http_call_response(m_call);
                ScheduleOnQueue();
            }

            Succeed();
        }
        catch (...) // needs good catch into setup
        {
            Fail(E_FAIL);
        }

    private:
        HCCallHandle const m_call;
        XTaskQueueHandle const m_queue;
        XTaskQueueHandle m_nestedQueue;
    };

    return Runner::MakeAndRun(
        reinterpret_cast<void*>(HCHttpCallPerformAsync),
        __FUNCTION__,
        asyncBlock,
        call,
        asyncBlock->queue
    );
}
CATCH_RETURN()

STDAPI_(uint64_t)
HCHttpCallGetId(
    _In_ HCCallHandle call
    ) noexcept
try
{
    if (call == nullptr)
    {
        return 0;
    }
    return call->id;
}
CATCH_RETURN()

STDAPI
HCHttpCallSetTracing(
    _In_ HCCallHandle call,
    _In_ bool logCall
    ) noexcept
try
{
    if (call == nullptr)
    {
        return E_INVALIDARG;
    }
    call->traceCall = logCall;
    return S_OK;
}
CATCH_RETURN()

STDAPI 
HCHttpCallSetContext(
    _In_ HCCallHandle call,
    _In_opt_ void* context
    ) noexcept
try
{
    if (call == nullptr)
    {
        return E_INVALIDARG;
    }

    call->context = context;

    return S_OK;
}
CATCH_RETURN()

STDAPI 
HCHttpCallGetContext(
    _In_ HCCallHandle call,
    _In_ void** context
    ) noexcept
try
{
    if (call == nullptr)
    {
        return E_INVALIDARG;
    }
    
    *context = call->context;

    return S_OK;
}
CATCH_RETURN()

STDAPI 
HCHttpCallGetRequestUrl(
    _In_ HCCallHandle call,
    _Out_ const char** url
    ) noexcept
try
{
    if (call == nullptr)
    {
        return E_INVALIDARG;
    }

    *url = call->url.data();
    return S_OK;
}
CATCH_RETURN()

bool http_header_compare::operator()(http_internal_string const& l, http_internal_string const& r) const
{
    return str_icmp(l, r) < 0;
}

void PerformEnvDeleter::operator()(HC_PERFORM_ENV* performEnv) noexcept
{
    Internal_CleanupHttpPlatform(performEnv);
}
