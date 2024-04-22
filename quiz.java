import java.sql.*;




public class TwitterTest {

  private static final String username = "root";

  private static final String password = "SpongebobSquarepantsWasATerribleCartoon";




  public static void main(String args[]) {

    try {

      Class.forName("com.mysql.jdbc.Driver");

      Connection conn = DriverManager.getConnection("jdbc:mysql://192.168.1.10:3306/twitter", username, password);

      Statement stmt = conn.createStatement();

      String theQuery = "SELECT tweet_text FROM tweets WHERE tweet_text = '" + args[0] + "'";

      ResultSet rs = stmt.executeQuery(theQuery);

      while (rs.next()) {

        System.out.println(rs.getString(2));

      }

    }

    catch (Exception e) {

      System.out.println("Whoops, something went terribly wrong! " + e.toString());

    }

  }

}

// 1. Compile via `javac TwitterTest.java`

// 2. Run via `java -classpath .:mysql-connector-java-5.1.40-bin.jar TwitterTest`
