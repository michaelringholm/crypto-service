using System;

namespace commentor.dk
{
    public class DependencyInjectionAttribute: Attribute
    {
        public DependencyInjectionAttribute(Type serviceInitializer) {
            Activator.CreateInstance(serviceInitializer);
        }
    }
}