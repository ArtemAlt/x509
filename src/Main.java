

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.*;
import java.sql.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
static FileInputStream is;
static X509Certificate t;
static Certificate cert;
static String subject;
static String serialNumber;
static String issuerPrincipal;
static String dNSName;
static String iPAddress ;
static String access;
static String encodedFile;
static byte [] decoded;
static Connection conn;
static PreparedStatement stmt;
static Logger logger = Logger.getLogger("Main");

    static public void main (String [] arg)  {

        try {
            File file = new File("C:\\Education\\Certificat_x509\\src\\access.txt");
            FileReader fr = new FileReader(file);
            BufferedReader reader = new BufferedReader(fr);
            access = reader.readLine();
            logger.log(Level.INFO,"Get access parameters");
            conn = DriverManager.getConnection(access);
            if (conn != null) {
                logger.log(Level.INFO,"Connected to the Postgres database!");
            } else {
                logger.log(Level.WARNING,"Failed to make connection!");
            }
        } catch (FileNotFoundException fnfe) {

            logger.log(Level.SEVERE,"Problem - file access", fnfe.getMessage());
        }
        catch (IOException e) {

            logger.log(Level.SEVERE,"Problem - reading file access", e.getMessage());
        }
        catch (SQLException e) {

            logger.log(Level.SEVERE,"Problem - SQL State: ",e.getSQLState());

        }
        catch (Exception e) {
            logger.log(Level.SEVERE,"Total exception",e.getMessage());
        }




        Scanner input = new Scanner(System.in);
        System.out.println("Input certificate *.cer");
        String path = input.next();
        logger.log(Level.INFO,"Input certificate");

        try {
                is = new FileInputStream(new File(path));
            } catch (FileNotFoundException e) {
            logger.log(Level.SEVERE,"File not found",e.getMessage());
            }

        CertificateFactory cf = null;
        try {
                cf = CertificateFactory.getInstance("X.509");

            } catch (CertificateException e) {
            logger.log(Level.SEVERE,"Certificate not found",e.getMessage());
            }

        try {
                assert cf != null;
                cert = cf.generateCertificate(is);
                t = (java.security.cert.X509Certificate) cert;
            } catch (CertificateException e) {
            logger.log(Level.SEVERE,"Certificate is not valid",e.getMessage());
           }

        decoded = convertFileToByteArray(path);
        encodedFile = Base64.getEncoder().encodeToString(decoded);
        logger.log(Level.INFO,"Convert *cer to Base64");

        try {
               subject  = t.getSubjectDN().toString();
               serialNumber = t.getSerialNumber().toString();
               issuerPrincipal = t.getIssuerX500Principal().toString();
               dNSName = getSubjectAltNames(t,2).toString();
               iPAddress = getSubjectAltNames(t,7).toString();

            logger.log(Level.INFO,"Parsing done");
             } catch (NullPointerException e){
            logger.log(Level.SEVERE,"Parsing error",e.getMessage());

        }

        try {
            String insertSql ="INSERT INTO cert VALUES (?,?,?,?,?,?)";
            stmt = conn.prepareStatement(insertSql);
            stmt.setString(1,subject);
            stmt.setString(2,serialNumber);
            stmt.setString(3,issuerPrincipal);
            stmt.setString(4,dNSName);
            stmt.setString(5,iPAddress);
            stmt.setString(6,encodedFile);
            stmt.executeUpdate();
            logger.log(Level.INFO,"SQL data base update");
        } catch (SQLException t) {
            logger.log(Level.SEVERE,"Couldn't update data base SQL",t.getSQLState());
        }
            System.out.println(subject);
            System.out.println(serialNumber);
            System.out.println(issuerPrincipal);
            System.out.println(dNSName);
            System.out.println(iPAddress);

        logger.log(Level.INFO,"Closing connection and releasing resources...");
        try {
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            logger.log(Level.WARNING,"Couldn't close connection to data base SQL",e.getMessage());
        }
            finally {
            if(stmt !=null){
                try {
                    stmt.close();
                } catch (SQLException e) {
                    logger.log(Level.WARNING,"Couldn't close JDBS stream to base SQL",e.getMessage());
                }
            }
            if(conn!=null){
                try {
                    conn.close();
                } catch (SQLException e) {
                    logger.log(Level.WARNING,"Couldn't close Driver Manager base SQL",e.getMessage());
                }
            }
        }
        System.out.println("Thank You.");
        logger.log(Level.INFO,"Programme finished");
    }


    private static byte[] convertFileToByteArray(String filePath) {

        Path path = Paths.get(filePath);

        byte[] codedFile = null;

        try {
            codedFile = Files.readAllBytes(path);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return codedFile;
    }

    private static List<String> getSubjectAltNames(X509Certificate certificate, int type) {
        List<String> result = new ArrayList<>();
        try {
            Collection<?> subjectAltNames = certificate.getSubjectAlternativeNames();
            if (subjectAltNames == null) {
                logger.log(Level.WARNING,"No SANs");
                return Collections.emptyList();

            }
            for (Object subjectAltName : subjectAltNames) {
                List<?> entry = (List<?>) subjectAltName;
                if (entry == null || entry.size() < 2) {
                    continue;
                }
                Integer altNameType = (Integer) entry.get(0);
                if (altNameType == null) {
                    continue;
                }
                if (altNameType == type) {
                    String altName = (String) entry.get(1);
                    if (altName != null) {
                        result.add(altName);
                    }
                }
            }
            return result;
        } catch (CertificateParsingException e) {
            return Collections.emptyList();
        }
    }

}
