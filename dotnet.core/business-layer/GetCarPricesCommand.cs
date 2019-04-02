using System;
using System.Collections.Generic;
using data_transport_layer;

namespace business_layer
{
    public class GetCarPricesCommand : ICommand
    {
        public dynamic Execute(dynamic input)
        {
            var carPrices = new List<CarPrice>();
            carPrices.Add(new CarPrice{ CarId = 100500, Price = 215000, Currency = "DKK"});
            carPrices.Add(new CarPrice{ CarId = 100505, Price = 325000, Currency = "DKK"});
            carPrices.Add(new CarPrice{ CarId = 100502, Price = 517000, Currency = "DKK"});
            carPrices.Add(new CarPrice{ CarId = 100507, Price = 118000, Currency = "DKK"});
            return carPrices;
        }
    }
}
