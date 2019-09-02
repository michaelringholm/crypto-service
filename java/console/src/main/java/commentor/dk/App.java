package commentor.dk;

/**
 * Hello world!
 */
public final class App {
    private App() {
    }

    /**
     * Says hello to the world.
     * @param args The arguments of the program.
     */
    public static void main(String[] args) {
        System.out.println("Starting web simulator!");
        WebSimulator.run();
        System.out.println("Web simulator done!");
    }
}
