using System;
using business_layer;
using Xunit;
using Xunit.Abstractions;

namespace business_layer_test
{
    public class GetCarPricesCommandTest
    {
        private ITestOutputHelper outputHelper;
        public GetCarPricesCommandTest(ITestOutputHelper outputHelper) {
            this.outputHelper = outputHelper;
        }

        [Fact]
        [Trait("Category","UnitTest")]
        public void Execute()
        {            
            var carPrices = new GetCarPricesCommand().Execute(null);
            Assert.Equal(4, carPrices.Count);
            Assert.Equal(100500, carPrices[0].CarId);
            Assert.Equal(325000, carPrices[1].Price);
            Assert.NotEqual(1, carPrices[1].Price);
        }
    }
}
