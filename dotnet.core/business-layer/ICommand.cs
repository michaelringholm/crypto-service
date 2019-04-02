namespace business_layer
{
    public interface ICommand
    {
        dynamic Execute(dynamic input);
    }
}