import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

public class BlobToPDFConverter {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the hexadecimal string: ");
        String hexString = scanner.nextLine();

        System.out.print("Enter the output PDF file path: ");
        String outputFilePath = scanner.nextLine();

        try {
            // Calculate the number of bytes
            int numberOfBytes = hexString.length() / 2;
            byte[] bytes = new byte[numberOfBytes];

            // Convert the hexadecimal string to bytes
            for (int i = 0; i < numberOfBytes; i++) {
                String byteStr = hexString.substring(i * 2, i * 2 + 2);
                bytes[i] = (byte) Integer.parseInt(byteStr, 16);
            }

            // Save the bytes as a PDF file
            FileOutputStream fos = new FileOutputStream(outputFilePath);
            fos.write(bytes);
            fos.close();

            System.out.println("PDF file saved successfully.");
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("An error occurred: " + e.getMessage());
        } catch (NumberFormatException e) {
            System.err.println("Invalid hexadecimal input.");
        } finally {
            scanner.close();
        }
    }
}










import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URISyntaxException;

public class SimpleAPICall {
    public static void main(String[] args) {
        HttpClient httpClient = HttpClient.newHttpClient();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI("https://jsonplaceholder.typicode.com/posts/1"))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            int statusCode = response.statusCode();
            String responseBody = response.body();
            HttpHeaders headers = response.headers();

            System.out.println("Status Code: " + statusCode);
            System.out.println("Response Body: " + responseBody);
            System.out.println("Response Headers: " + headers);
        } catch (IOException | InterruptedException | URISyntaxException e) {
            e.printStackTrace();
        }
    }
}


