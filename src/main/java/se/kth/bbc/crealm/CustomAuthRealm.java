package se.kth.bbc.crealm;

import com.sun.appserv.connectors.internal.api.ConnectorRuntime;
import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.digest.api.Password;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.common.Util;
import com.sun.enterprise.universal.GFBase64Encoder;
import com.sun.enterprise.util.Utility;
import com.yubico.base.Pof;
import com.yubico.base.Token;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.LoginException;
import org.jvnet.hk2.annotations.Service;
import javax.sql.DataSource;
import org.apache.commons.codec.binary.Base32;
import org.glassfish.hk2.api.ActiveDescriptor;
import org.glassfish.hk2.utilities.BuilderHelper;

/**
 *
 * @author Ali Gholami <gholami@pdc.kth.se>
 */
@Service(name = "CustomAuthRealm")
public class CustomAuthRealm extends AppservRealm {

    /**
     * Adapted from
     * http://grepcode.com/file/repo1.maven.org/maven2/org.glassfish.security/security/3.0.1/com/sun/enterprise/security/auth/realm/jdbc/JDBCRealm.java
     * and
     * https://weblogs.java.net/blog/evanx/archive/2012/11/07/google-authenticator-thus-enabled
     * and
     * https://code.google.com/p/yubikey-server-j/
     */
    /* To distinguish between Yubikey and Mobile users authentication*/
    private final String YUBIKEY_USER_MARKER = "YUBIKEY_USER_MARKER";

    /* TOTP default time interval*/
    public static final long KEY_VALIDATION_INTERVAL_MS
            = TimeUnit.SECONDS.toMillis(30);

    public static final int SECRET_KEY_MODULE = 1000 * 1000;

    // Descriptive string of the authentication type of this realm.
    public static final String AUTH_TYPE = "cauth";
    public static final String PRE_HASHED = "HASHED";
    public static final String PARAM_DATASOURCE_JNDI = "datasource-jndi";

    public static final String PARAM_DIGEST_ALGORITHM = "digest-algorithm";
    public static final String DEFAULT_DIGEST_ALGORITHM = "SHA-256";
    public static final String NONE = "none";

    public static final String PARAM_ENCODING = "encoding";
    public static final String HEX = "hex";
    public static final String BASE64 = "base64";
    public static final String DEFAULT_ENCODING = HEX; // for digest only

    public static final String PARAM_CHARSET = "charset";

    public static final String PARAM_USER_TABLE = "user-table";
    public static final String PARAM_USER_NAME_COLUMN = "user-name-column";
    public static final String PARAM_PASSWORD_COLUMN = "password-column";
    public static final String PARAM_OTP_COLUMN = "otp-secret-column"; // for the one time password
    public static final String PARAM_GROUP_TABLE = "group-table";
    public static final String PARAM_GROUP_NAME_COLUMN = "group-name-column";
    public static final String PARAM_GROUP_TABLE_USER_NAME_COLUMN = "group-table-user-name-column";
    public static final String PARAM_USER_STATUS = "user-status-column";
    public static final String PARAM_YUBIKEY_TABLE = "yubikey-table";

    /*
     public static final String PARAM_YUBIKEY_ID_COLUMN = "yubikey-id-column";
     public static final String PARAM_YUBIKEY_SECRET_COLUMN = "yubikey-secret-column";
     public static final String PARAM_YUBIKEY_STATUS = "yubikey-status-column";
     public static final String PARAM_YUBIKEY_USERID_COLUMN = "yubikey-userid-column";
     public static final String PARAM_YUBIKEY_COUNTER_COLUMN = "yubikey-counter-column";
     public static final String PARAM_YUBIKEY_SESSION_COLUMN = "yubikey-session-column";
     public static final String PARAM_YUBIKEY_HIGH_COLUMN = "yubikey-high-column";
     public static final String PARAM_YUBIKEY_LOW_COLUMN = "yubikey-low-column";
     */
    private static final char[] HEXADECIMAL = {'0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private Map<String, Vector> groupCache;
    private Vector<String> emptyVector;
    private String passwordQuery = null;
    private String groupQuery = null;
    private String yubikeyUpdateQuery = null;
    private String selectYubikey = null;
    private MessageDigest md = null;
    Properties prop = null;
   
        private ActiveDescriptor<ConnectorRuntime> cr;


    @Override
    public String getAuthType() {
        return AUTH_TYPE; //To change body of generated methods, choose Tools | Templates.
    }

    public String[] authenticate(String username, String password) {
    
        String[] groups = null;
        // make a yubikey check
        if (password.endsWith(YUBIKEY_USER_MARKER)) {
            String hpwd = password.substring(0, password.length() - YUBIKEY_USER_MARKER.length());
            if (isValidYubikeyUser(username, hpwd)) {
                groups = findGroups(username);
                groups = addAssignGroups(groups);
                setGroupNames(username, groups);
            }

        }

        if (isValidMobileUser(username, password)) {
            groups = findGroups(username);
            groups = addAssignGroups(groups);
            setGroupNames(username, groups);
        }
        return groups;
    }

    public synchronized void init(Properties props)
            throws BadRealmException, NoSuchRealmException {
        super.init(props);
        String jaasCtx = props.getProperty(IASRealm.JAAS_CONTEXT_PARAM);
        String dsJndi = props.getProperty(PARAM_DATASOURCE_JNDI);
        String digestAlgorithm = props.getProperty(PARAM_DIGEST_ALGORITHM,
                DEFAULT_DIGEST_ALGORITHM);
        String encoding = props.getProperty(PARAM_ENCODING);
        String charset = props.getProperty(PARAM_CHARSET);
        String userTable = props.getProperty(PARAM_USER_TABLE);
        String userNameColumn = props.getProperty(PARAM_USER_NAME_COLUMN);
        String passwordColumn = props.getProperty(PARAM_PASSWORD_COLUMN);
        String otpColumn = props.getProperty(PARAM_OTP_COLUMN);
        String groupTable = props.getProperty(PARAM_GROUP_TABLE);
        String groupNameColumn = props.getProperty(PARAM_GROUP_NAME_COLUMN);
        String groupTableUserNameColumn = props.getProperty(PARAM_GROUP_TABLE_USER_NAME_COLUMN, userNameColumn);
        String userActiveColumn = props.getProperty(PARAM_USER_STATUS);
        String yubikeyTable = props.getProperty(PARAM_YUBIKEY_TABLE);

        
        /*
         String yubikeyId = props.getProperty(PARAM_YUBIKEY_ID_COLUMN);
         String yubikeyStatus = props.getProperty(PARAM_YUBIKEY_STATUS);
         String yubikeyUid = props.getProperty(PARAM_YUBIKEY_USERID_COLUMN);
         String yubikeyHigh = props.getProperty(PARAM_YUBIKEY_HIGH_COLUMN);
         String yubikeyLow = props.getProperty(PARAM_YUBIKEY_LOW_COLUMN);
         String yubikeySecret = props.getProperty(PARAM_YUBIKEY_SECRET_COLUMN);
         String yubikeySessionUse = props.getProperty(PARAM_YUBIKEY_SESSION_COLUMN);
         String yubikeySessionCounter = props.getProperty(PARAM_YUBIKEY_COUNTER_COLUMN);
         */
     	cr = (ActiveDescriptor<ConnectorRuntime>)
                Util.getDefaultHabitat().getBestDescriptor(BuilderHelper.createContractFilter(ConnectorRuntime.class.getName()));


        // load the properties to enable/disable the realm
        prop = new Properties();
        try {
            InputStream inputStream
                    = getClass().getClassLoader().getResourceAsStream("cauth.properties");
            prop.load(inputStream);
        } catch (IOException ex) {
            Logger.getLogger(CustomAuthRealm.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (jaasCtx == null) {
            String msg = sm.getString(
                    "realm.missingprop", IASRealm.JAAS_CONTEXT_PARAM, "CustomAuthRealm");
            throw new BadRealmException(msg);
        }

        if (dsJndi == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_DATASOURCE_JNDI, "CustomAuthRealm");
            throw new BadRealmException(msg);
        }
        if (userTable == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_USER_TABLE, "CustomAuthRealm");
            throw new BadRealmException(msg);
        }
        if (groupTable == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_GROUP_TABLE, "CustomAuthRealm");
            throw new BadRealmException(msg);
        }
        if (userNameColumn == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_USER_NAME_COLUMN, "CustomAuthRealm");
            throw new BadRealmException(msg);
        }
        if (passwordColumn == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_PASSWORD_COLUMN, "CustomAuthRealm");
            throw new BadRealmException(msg);
        }
        if (groupNameColumn == null) {
            String msg = sm.getString(
                    "realm.missingprop", PARAM_GROUP_NAME_COLUMN, "CustomAuthRealm");
            throw new BadRealmException(msg);
        }
        if (yubikeyTable == null) {
            yubikeyTable = "Yubikey";
        }

        passwordQuery = "SELECT " + passwordColumn + " , " + otpColumn + ", " + userActiveColumn + " FROM " + userTable
                + " WHERE " + userNameColumn + " = ?";

        groupQuery = "SELECT " + groupNameColumn + " FROM " + groupTable
                + " WHERE " + groupTableUserNameColumn + " = ? ";

        yubikeyUpdateQuery = "update " + yubikeyTable + " set accessed=?, counter=?, "
                + "high=?, low=?, session_use=? where public_id=?";

        selectYubikey = "select * from " + yubikeyTable + " where public_id = ?";

        if (!NONE.equalsIgnoreCase(digestAlgorithm)) {
            try {
                md = MessageDigest.getInstance(digestAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                String msg = sm.getString("cauth realm.notsupportdigestalg",
                        digestAlgorithm);
                throw new BadRealmException(msg);
            }
        }
        if (md != null && encoding == null) {
            encoding = DEFAULT_ENCODING;
        }

        this.setProperty(IASRealm.JAAS_CONTEXT_PARAM, jaasCtx);
        this.setProperty(PARAM_DATASOURCE_JNDI, dsJndi);
        this.setProperty(PARAM_DIGEST_ALGORITHM, digestAlgorithm);
        if (encoding != null) {
            this.setProperty(PARAM_ENCODING, encoding);
        }
        if (charset != null) {
            this.setProperty(PARAM_CHARSET, charset);
        }

        if (_logger.isLoggable(Level.FINEST)) {
            _logger.finest("CustomAuthRealm : "
                    + IASRealm.JAAS_CONTEXT_PARAM + "= " + jaasCtx + ", "
                    + PARAM_DATASOURCE_JNDI + " = " + dsJndi + ", "
                    + PARAM_DIGEST_ALGORITHM + " = " + digestAlgorithm + ", "
                    + PARAM_ENCODING + " = " + encoding + ", "
                    + PARAM_CHARSET + " = " + charset);
        }

        groupCache = new HashMap<String, Vector>();
        emptyVector = new Vector<String>();
    
    }

    private void close(Connection conn, PreparedStatement stmt,
            ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (Exception ex) {
            }
        }

        if (stmt != null) {
            try {
                stmt.close();
            } catch (Exception ex) {
            }
        }

        if (conn != null) {
            try {
                conn.close();
            } catch (Exception ex) {
            }
        }
    }

    private Connection getConnection() throws LoginException {

        final String dsJndi = this.getProperty(PARAM_DATASOURCE_JNDI);
        try {
            String nonTxJndiName = dsJndi + "__nontx";
            /*InitialContext ic = new InitialContext();
             final DataSource dataSource = 
             //V3 Commented (DataSource)ConnectorRuntime.getRuntime().lookupNonTxResource(dsJndi,false);
             //replacement code suggested by jagadish
             (DataSource)ic.lookup(nonTxJndiName);*/
   ConnectorRuntime connectorRuntime = Util.getDefaultHabitat().getServiceHandle(cr).getService();
            final DataSource dataSource =
                (DataSource) connectorRuntime.lookupNonTxResource(dsJndi,false);
            
            //(DataSource)ConnectorRuntime.getRuntime().lookupNonTxResource(dsJndi,false);
            Connection connection = null;
            connection = dataSource.getConnection();
            return connection;
        } catch (Exception ex) {
            String msg = sm.getString("cauth realm.cantconnect", dsJndi);
            LoginException loginEx = new LoginException(msg);
            loginEx.initCause(ex);
            throw loginEx;
        }
    
    }


     private String hashPassword( String password)
            throws CharacterCodingException {
        char [] pass = password.toCharArray();
        byte[] bytes = null;
        char[] result = null;
        String charSet = getProperty(PARAM_CHARSET);
        bytes = Utility.convertCharArrayToByteArray(pass, charSet);

        if (md != null) {
            synchronized(md) {
                md.reset();
                bytes = md.digest(bytes);
            }
        }

        String encoding = getProperty(PARAM_ENCODING);
        if (HEX.equalsIgnoreCase(encoding)) {
            result = hexEncode(bytes);
        } else if (BASE64.equalsIgnoreCase(encoding)) {
            result = base64Encode(bytes).toCharArray();
        } else { // no encoding specified                                                                                                                                
            result = Utility.convertByteArrayToCharArray(bytes, charSet);
        }
        return String.valueOf(result);
     }        
    
    private char[] hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(2 * bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            int low = (int) (bytes[i] & 0x0f);
            int high = (int) ((bytes[i] & 0xf0) >> 4);
            sb.append(HEXADECIMAL[high]);
            sb.append(HEXADECIMAL[low]);
        }
        char[] result = new char[sb.length()];
        sb.getChars(0, sb.length(), result, 0);
        return result;
    }


    private String base64Encode(byte[] bytes) {
        GFBase64Encoder encoder = new GFBase64Encoder();
        return encoder.encode(bytes);
    }

    private boolean isValidYubikeyUser(String user, String password) {
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        boolean valid = false;

        try {
            // Get the original password
            String hpwd = hashPassword(password.substring(0, password.length() - 44));

            // Get the 44 digit OTP code
            String otpCode = password.substring(password.length() - 44).toLowerCase();

            int len = otpCode.length();
            int split = len - 32;

            // Get connedcted to DB and find the user
            connection = getConnection();
            statement = connection.prepareStatement(passwordQuery);
            statement.setString(1, user);
            rs = statement.executeQuery();
            String pwd = null;
            if (rs.next()) {
                // Get the user's credentials
                pwd = rs.getString(1);
                String otp = rs.getString(2);
                int status = Integer.parseInt(rs.getString(3));

                if (HEX.equalsIgnoreCase(getProperty(PARAM_ENCODING))) {
                    // for only normal password
                    if (prop.getProperty("cauth-realm-enabled").equals("false")) {
                        _logger.info("## CustomAuthRealm disabled.");
                        valid = pwd.equalsIgnoreCase(hpwd);
                    } else {

                        valid = validateOTP(otpCode.substring(0, 12), otpCode.substring(split)) && ((status == 1) || (status == 0));
                        // valid = pwd.equalsIgnoreCase(hpwd) && verifyCode(otp, Integer.parseInt(otpCode), getTimeIndex(), 5) && ((status==1)|| (status==0));
                    }
                } else {
                    // for only normal password
                    if (prop.getProperty("cauth-realm-enabled").equals("false")) {
                        _logger.info("## CustomAuthRealm disabled.");
                        valid = pwd.equalsIgnoreCase(hpwd);
                    } else {
                        valid = validateOTP(otpCode.substring(0, 12), otpCode.substring(split)) && ((status == 1) || (status == 0));
                        //valid = pwd.equals(hpwd) && verifyCode(otp, Integer.parseInt(otpCode.trim()), getTimeIndex(), 5) && ((status==1) || (status ==0));
                    }
                }
            }
        } catch (SQLException ex) {
            _logger.log(Level.SEVERE, "cauthrealm.invaliduserreason",
                    new String[]{user, ex.toString()});
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } catch (Exception ex) {
            _logger.log(Level.SEVERE, "cauth realm.invaliduser", user);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } finally {
            close(connection, statement, rs);
        }
        return valid;
    }

    private boolean isValidMobileUser(String user, String password) {
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
       
        boolean valid = true;

        try {

            // Get the original password
            String hpwd = hashPassword(password.substring(0, password.length() - 6));

            // Get the 6 digit OTP code
            String otpCode = password.substring(password.length() - 6);

            // Get connedcted to DB and find the user
            connection = getConnection();
            statement = connection.prepareStatement(passwordQuery);
            statement.setString(1, user);
            rs = statement.executeQuery();
            String pwd = null;
            if (rs.next()) {
                // Get the user's credentials
                pwd = rs.getString(1);
                String otp = rs.getString(2);
                int status = Integer.parseInt(rs.getString(3));

                if (HEX.equalsIgnoreCase(getProperty(PARAM_ENCODING))) {
                    // for only normal password
                    if (prop.getProperty("cauth-realm-enabled").equals("false")) {
                        _logger.info("## CustomAuthRealm disabled.");
                        
                        valid = pwd.equalsIgnoreCase(hpwd);
                    } else {
                        valid = pwd.equalsIgnoreCase(hpwd) && verifyCode(otp, Integer.parseInt(otpCode), getTimeIndex(), 5) && ((status == 1) || (status == 0));
                    }
                } else {
                    // for only normal password
                    if (prop.getProperty("cauth-realm-enabled").equals("false")) {
                        _logger.info("## CustomAuthRealm disabled.");
                        valid = pwd.equalsIgnoreCase(hpwd);
                    } else {
                        valid = pwd.equals(hpwd) && verifyCode(otp, Integer.parseInt(otpCode.trim()), getTimeIndex(), 5) && ((status == 1) || (status == 0));
                    }
                }
            }
        } catch (SQLException ex) {
            _logger.log(Level.SEVERE, "cauthrealm.invaliduserreason",
                    new String[]{user, ex.toString()});
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } catch (Exception ex) {
            _logger.log(Level.SEVERE, "cauth realm.invaliduser", user);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } finally {
            close(connection, statement, rs);
        }
        return valid;
    }

    private Password getPassword(String username) {

        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        boolean valid = false;

        try {
            connection = getConnection();
            statement = connection.prepareStatement(passwordQuery);
            statement.setString(1, username);
            rs = statement.executeQuery();

            if (rs.next()) {
                // Split the merged password and otp
                final String pwd = rs.getString(1);
                final String otp = rs.getString(2).trim();
                if (!PRE_HASHED.equalsIgnoreCase(getProperty(PARAM_ENCODING))) {
                    return new Password() {

                        public byte[] getValue() {
                            return pwd.getBytes();
                        }

                        public int getType() {
                            return Password.PLAIN_TEXT;
                        }

                    };
                } else {
                    return new Password() {

                        public byte[] getValue() {
                            return pwd.getBytes();
                        }

                        public int getType() {
                            return Password.HASHED;
                        }

                    };
                }
            }
        } catch (LoginException | SQLException ex) {
            _logger.log(Level.SEVERE, "cauth realm.invaliduser", username);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot validate user", ex);
            }
        } finally {
            close(connection, statement, rs);
        }
        return null;

    }

    @Override
    public Enumeration getGroupNames(String username)
            throws InvalidOperationException, NoSuchUserException {
        Vector vector = groupCache.get(username);
        if (vector == null) {
            String[] grps = findGroups(username);
            setGroupNames(username, grps);
            vector = groupCache.get(username);
        }
        return vector.elements();
    }

    private String[] findGroups(String user) {
        Connection connection = null;
        PreparedStatement statement = null;
        ResultSet rs = null;
        try {
            connection = getConnection();
            statement = connection.prepareStatement(groupQuery);
            statement.setString(1, user);
            rs = statement.executeQuery();
            final List<String> groups = new ArrayList<String>();
            while (rs.next()) {
                groups.add(rs.getString(1));
            }
            final String[] groupArray = new String[groups.size()];
            return groups.toArray(groupArray);
        } catch (Exception ex) {
            _logger.log(Level.SEVERE, "cauth realm.grouperror", user);
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "Cannot load group", ex);
            }
            return null;
        } finally {
            close(connection, statement, rs);
        }
    }

    private void setGroupNames(String username, String[] groups) {
        Vector<String> v = null;

        if (groups == null) {
            v = emptyVector;

        } else {
            v = new Vector<String>(groups.length + 1);
            for (int i = 0; i < groups.length; i++) {
                v.add(groups[i]);
            }
        }

        synchronized (this) {
            groupCache.put(username, v);
        }
    }

    /**
     * Verify the received user one time password code against the stored
     * secret,
     *
     * @param secret
     * @param code
     * @param timeIndex
     * @param variance
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static boolean verifyCode(String secret, long code, long timeIndex, int variance)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        for (int i = -variance; i <= variance; i++) {
            if (getCode(decodedKey, timeIndex + i) == code) {
                return true;
            }
        }
        return false;
    }

    public static long getTimeIndex() {
        return System.currentTimeMillis() / 1000 / 30;
    }

    /**
     * Generate the otp code according to some definitions.
     *
     * @param secret
     * @param timeIndex
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static long getCode(byte[] secret, long timeIndex)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signKey = new SecretKeySpec(secret, "HmacSHA1");
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(timeIndex);
        byte[] timeBytes = buffer.array();
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(timeBytes);
        int offset = hash[19] & 0xf;
        long truncatedHash = hash[offset] & 0x7f;
        for (int i = 1; i < 4; i++) {
            truncatedHash <<= 8;
            truncatedHash |= hash[offset + i] & 0xff;
        }
        return (truncatedHash %= 1000000);
    }

    private void updateYubikeyOnTokenId(int sessionCounter, int hi, int lo, int sessionUse, String public_id) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            conn = getConnection();

            stmt = conn.prepareStatement(yubikeyUpdateQuery);
            long l = new java.util.Date().getTime();
            stmt.setTimestamp(1, new java.sql.Timestamp(l));
            stmt.setInt(2, sessionCounter);
            stmt.setInt(3, hi);
            stmt.setInt(4, lo);
            stmt.setInt(5, sessionUse);
            stmt.setString(6, public_id);
            int num = stmt.executeUpdate();
            if (num < 1) {
                throw new SQLException("Internal error, num=" + num);
            }
        } catch (SQLException | LoginException ex) {
            Logger.getLogger(CustomAuthRealm.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            close(conn, stmt, rs);
        }
    }

 
    /**
     * 
     * @param public_id
     * @param otp
     * @return 
     */
    private boolean validateOTP(String public_id, String otp) {
    
        Connection conn = null;
        PreparedStatement stmt = null;
        ResultSet rs = null;

        try {
            conn = getConnection();
            stmt = conn.prepareStatement(selectYubikey);
            stmt.setString(1, public_id);
            rs = stmt.executeQuery();

            if (!rs.first()) {
                return false;
            }
            if (rs.getInt("status") != AccountStatus.ACCOUNT_ACTIVE) {
                return false;
            }

            String secret = rs.getString("aes_secret");
            int seenSessionCounter = rs.getInt("counter");
            int seenHi = rs.getInt("high");
            int seenLo = rs.getInt("low");
            int seenSessionUse = rs.getInt("session_use");

            Token t;
            t = Pof.parse(otp, hexStringToByteArray(secret));
            int sessionCounter = toInt(t.getSessionCounter());
            int scDiff = seenSessionCounter - sessionCounter;

            int sessionUse = t.getTimesUsed();
            int suDiff = seenSessionUse - sessionUse;

            int hi = t.getTimestampHigh() & 0xff;
            int hiDiff = seenHi - hi;

            int lo = toInt(t.getTimestampLow());
            int loDiff = seenLo - lo;

            if (scDiff > 0) {
                return false;
            }
            if (scDiff == 0 && suDiff > 0) {
                return false;
            }
            if (scDiff == 0 && suDiff == 0 && hiDiff > 0) {
                return false;
            }
            if (scDiff == 0 && suDiff == 0 && hiDiff == 0 && loDiff > 0) {
                return false;
            }
            if (scDiff == 0 && suDiff == 0 && hiDiff == 0 && loDiff == 0) {
                return false;
            }

            updateYubikeyOnTokenId(sessionCounter, hi, lo, sessionUse, public_id);

        } catch (SQLException | GeneralSecurityException ex) {
            Logger.getLogger(CustomAuthRealm.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            close(conn, stmt, rs);
        }

        return true;
    }

    public int toInt(byte[] arr) {
        int low = arr[0] & 0xff;
        int high = arr[1] & 0xff;
        return (int) (high << 8 | low);
    }

    public String getTimeStamp() {
        SimpleDateFormat sdf
                = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'SSSS");
        Date tmp = new Date();
        return sdf.format(tmp);
    }

    
    private byte[] hexStringToByteArray(String encoded) {
        if ((encoded.length() % 2) != 0) {
            throw new IllegalArgumentException("Input string must contain an even number of characters");
        }

        final byte result[] = new byte[encoded.length() / 2];
        final char enc[] = encoded.toCharArray();
        for (int i = 0; i < enc.length; i += 2) {
            StringBuilder curr = new StringBuilder(2);
            curr.append(enc[i]).append(enc[i + 1]);
            result[i / 2] = (byte) Integer.parseInt(curr.toString(), 16);
        }
        return result;
    }
}