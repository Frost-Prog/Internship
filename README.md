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









import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class SimpleAPICall {
    public static void main(String[] args) {
        try {
            URL url = new URL("https://jsonplaceholder.typicode.com/posts/1");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();

            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                System.out.println("Response Code: " + responseCode);
                System.out.println("Response Body: " + response.toString());
            } else {
                System.out.println("HTTP GET request failed with response code: " + responseCode);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

