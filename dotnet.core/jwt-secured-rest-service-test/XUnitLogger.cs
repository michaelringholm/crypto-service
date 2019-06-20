using System;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace jwt_secured_rest_service_test
{
    public class XUnitLogger : ILogger
    {
        private ITestOutputHelper outputHelper;
        public XUnitLogger(ITestOutputHelper outputHelper)
        {
            this.outputHelper = outputHelper;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            throw new NotImplementedException();
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            throw new NotImplementedException();
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            outputHelper.WriteLine("test");
        }
    }
}