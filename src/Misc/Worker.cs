using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace windows_exploration
{
    public class Worker<T>
    {
        private readonly Func<CancellationToken, Task<T>> _executeFunction;
        private readonly Action<Exception> _errorCallback;
        private static ConcurrentQueue<T> _outputQueue = new ConcurrentQueue<T>();
        private CancellationTokenSource _cts = new CancellationTokenSource();

        public Worker(Func<CancellationToken, Task<T>> executeFunction, Action<Exception> errorCallback = null)
        {
            _executeFunction = executeFunction ?? throw new ArgumentNullException(nameof(executeFunction));
            _errorCallback = errorCallback;
        }

        public static ConcurrentQueue<T> OutputQueue => _outputQueue;

        public void Start()
        {
            Task.Run(async () =>
            {
                try
                {
                    T result = await _executeFunction(_cts.Token);
                    _outputQueue.Enqueue(result);
                }
                catch (Exception ex)
                {
                    _errorCallback?.Invoke(ex);
                }
            });
        }

        public void Stop()
        {
            _cts.Cancel();
        }
    }
}
