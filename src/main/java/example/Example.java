package example;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import io.hotmoka.beans.requests.ConstructorCallTransactionRequest;
import io.hotmoka.beans.requests.InstanceMethodCallTransactionRequest;
import io.hotmoka.beans.requests.SignedTransactionRequest;
import io.hotmoka.beans.requests.SignedTransactionRequest.Signer;
import io.hotmoka.beans.signatures.CodeSignature;
import io.hotmoka.beans.signatures.ConstructorSignature;
import io.hotmoka.beans.signatures.NonVoidMethodSignature;
import io.hotmoka.beans.types.BasicTypes;
import io.hotmoka.beans.types.ClassType;
import io.hotmoka.beans.values.BigIntegerValue;
import io.hotmoka.beans.values.BooleanValue;
import io.hotmoka.beans.values.IntValue;
import io.hotmoka.beans.values.StorageReference;
import io.hotmoka.beans.values.StringValue;
import io.hotmoka.crypto.Base58;
import io.hotmoka.crypto.SignatureAlgorithm;
import io.hotmoka.crypto.SignatureAlgorithmForTransactionRequests;
import io.hotmoka.helpers.GasHelper;
import io.hotmoka.helpers.ManifestHelper;
import io.hotmoka.helpers.MintBurnHelper;
import io.hotmoka.helpers.NonceHelper;
import io.hotmoka.nodes.Node;
import io.hotmoka.remote.RemoteNode;
import io.hotmoka.remote.RemoteNodeConfig;

public class Example {

	// l'URL a cui vogliamo connetterci. Dovrebbe essere il nodo che ha installato Giovanni, quindi qualcosa come my-node.com:80
	public final static String URL = "localhost:80";

	public static void main(String[] args) throws Exception {
		// la configurazione del nodo remoto a cui vogliamo connetterci
		RemoteNodeConfig config = new RemoteNodeConfig.Builder().setURL(URL).build();

		// ci connettiamo al nodo remoto
		try (Node node = RemoteNode.of(config)) {
			// eseguiamo le transazioni di esempio
			new Example(node);
		}
	}

	private final BigInteger SOME_GAS = BigInteger.valueOf(1_000_000L);
	private final SignatureAlgorithm<SignedTransactionRequest> ed25519 = SignatureAlgorithmForTransactionRequests.ed25519();

	// le crypto di cui si fa il mint per l'account di Iris
	private final BigInteger IRIS_FUNDS = BigInteger.valueOf(10_000_000_000L);

	private final Node node;

	private Example(Node node) throws Exception {
		this.node = node;

		gameteFundsIris();
		StorageReference erc20 = IrisCreatesERC20Contract();
		IrisSends10TokensToGamete(erc20);
		IrisChecksHisBalance(erc20);
	}

	/**
	 * Il gamete fa il mint di un po' di crypto per l'account di Iris.
	 * Solo il gamete può fare questo "by magic", senza pagare nulla!
	 */
	private void gameteFundsIris() throws Exception {
		MintBurnHelper mintBurnHelper = new MintBurnHelper(node);
		StorageReference reference = mintBurnHelper.mint(getKeysOfGamete(), ed25519, new String(Base64.getEncoder().encode(ed25519.encodingOf(getKeysOfIris().getPublic()))), IRIS_FUNDS);
		System.out.println("I minted " + IRIS_FUNDS + " coins for the account of Iris, that is allocated at reference " + reference);
	}

	/**
	 * Iris crea in blockchain un'istanza di contratto ERC20.
	 * Inizialmente ci sono 100 token, tutti in possesso di Iris.
	 */
	private StorageReference IrisCreatesERC20Contract() throws Exception {
		KeyPair keys = getKeysOfIris();
		ManifestHelper manifestHelper = new ManifestHelper(node);
		NonceHelper nonceHelper = new NonceHelper(node);
		GasHelper gasHelper = new GasHelper(node);

		// cerchiamo a quale reference è allocato l'account di Iris, partendo dalla sua chiave pubblica
		StorageReference iris = getReferenceFromPublicKey(keys.getPublic(), manifestHelper);

		// poi usiamo l'account di Iris per chiamare il costruttore della classe io.takamaka.code.tokens.ERC20
		StorageReference erc20 = node.addConstructorCallTransaction(new ConstructorCallTransactionRequest
			(Signer.with(ed25519, keys),
			iris, // caller
			nonceHelper.getNonceOf(iris),
			manifestHelper.getChainId(),
			SOME_GAS,
			gasHelper.getSafeGasPrice(),
			manifestHelper.takamakaCode,
			new ConstructorSignature(ClassType.ERC20, ClassType.STRING, ClassType.STRING, BasicTypes.INT),
			new StringValue("CryptoBuddy"), // nome del token
			new StringValue("CB"), // simbolo del token
			new IntValue(100) // initial supply, associata al caller (quindi ad Iris)
		));

		System.out.println("I created a new ERC20 contract at reference " + erc20 + ", where Iris holds 100 tokens initially");

		return erc20;
	}

	/**
	 * Iris spedisce al gametet 10 token dal suo bilancio nel contratto ERC20.
	 */
	private void IrisSends10TokensToGamete(StorageReference erc20) throws Exception {
		KeyPair keys = getKeysOfIris();
		ManifestHelper manifestHelper = new ManifestHelper(node);
		NonceHelper nonceHelper = new NonceHelper(node);
		GasHelper gasHelper = new GasHelper(node);

		// cerchiamo a quale reference è allocato l'account di Iris, partendo dalla sua chiave pubblica
		StorageReference iris = getReferenceFromPublicKey(keys.getPublic(), manifestHelper);

		// poi usiamo l'account di Iris per chiamare il metodo "erc20.transfer(gamete, 10)", in modo da mandare
		// 10 token di Iris al gamete; tale metodo ritorna un booleano per indicare il successo o meno del trasferimento
		BooleanValue result = (BooleanValue) node.addInstanceMethodCallTransaction(new InstanceMethodCallTransactionRequest
			(Signer.with(ed25519, keys),
			iris, // caller
			nonceHelper.getNonceOf(iris),
			manifestHelper.getChainId(),
			SOME_GAS,
			gasHelper.getSafeGasPrice(),
			manifestHelper.takamakaCode,
			new NonVoidMethodSignature(ClassType.ERC20, "transfer", BasicTypes.BOOLEAN, ClassType.CONTRACT, BasicTypes.INT),
			erc20,
			manifestHelper.gamete, new IntValue(10)));

		System.out.println("Iris sent 10 tokens to the gamete. Success = " + result);
	}

	/**
	 * Iris legge il suo bilancio nel contratto ERC20.
	 */
	private void IrisChecksHisBalance(StorageReference erc20) throws Exception {
		KeyPair keys = getKeysOfIris();
		ManifestHelper manifestHelper = new ManifestHelper(node);

		// cerchiamo a quale reference è allocato l'account di Iris, partendo dalla sua chiave pubblica
		StorageReference iris = getReferenceFromPublicKey(keys.getPublic(), manifestHelper);

		// poi usiamo l'account di Iris per leggere il suo bilancio, chiamando il metodo "erc20.balanceOf(iris)",
		// che ritorna un UnsignedBigInteger; si tratta di un metodo @View, quindi non serve firmare la chiamata
		StorageReference balance = (StorageReference) node.runInstanceMethodCallTransaction(new InstanceMethodCallTransactionRequest
			(iris, // caller
			SOME_GAS,
			manifestHelper.takamakaCode,
			new NonVoidMethodSignature(ClassType.ERC20, "balanceOf", ClassType.UNSIGNED_BIG_INTEGER, ClassType.CONTRACT),
			erc20,
			iris));

		// il balance è un UnsignedBigInteger: ne leggiamo il valore chiamando balance.toBigInteger(), anch'esso @View
		BigIntegerValue value = (BigIntegerValue) node.runInstanceMethodCallTransaction(new InstanceMethodCallTransactionRequest
			(iris, // caller
			SOME_GAS,
			manifestHelper.takamakaCode,
			new NonVoidMethodSignature(ClassType.UNSIGNED_BIG_INTEGER, "toBigInteger", ClassType.BIG_INTEGER),
			balance
		));

		System.out.println("Iris has balance " + value + " in the ERC20 contract now");
	}

	private StorageReference getReferenceFromPublicKey(PublicKey publicKey, ManifestHelper manifestHelper) throws Exception {
		return (StorageReference) node.runInstanceMethodCallTransaction(new InstanceMethodCallTransactionRequest
			(manifestHelper.gamete, SOME_GAS, manifestHelper.takamakaCode, CodeSignature.GET_FROM_ACCOUNTS_LEDGER, manifestHelper.accountsLedger,
			new StringValue(new String(Base64.getEncoder().encode(ed25519.encodingOf(publicKey))))));
	}

	/**
	 * Restituisce le chiavi del gamete del nodo. Si noti che la chiave pubblica deve essere quella
	 * fornita a docker per il gamete, quando si è fatto partire il nodo!
	 */
	private KeyPair getKeysOfGamete() throws InvalidKeySpecException, NoSuchAlgorithmException {
		PrivateKey privateKey = ed25519.privateKeyFromEncoding(Base58.decode("AAXS4qJ8KdRZaM9KL9HAPkmDEDTPxk6QTcUkEQCEwScP"));
		
		// la stessa passata a docker!
		PublicKey publicKey = ed25519.publicKeyFromEncoding(Base58.decode("5TikBT5bHFw8PTy8a87dWVWhVB14eVeEbMzMEMbYw4bE"));

		return new KeyPair(publicKey, privateKey);
	}

	/**
	 * Restituisce le chiavi con cui Iris controlla il suo account.
	 */
	private KeyPair getKeysOfIris() throws InvalidKeySpecException, NoSuchAlgorithmException {
		PrivateKey privateKey = ed25519.privateKeyFromEncoding(Base58.decode("2uPcjQYkLHurif9weEoefR91U5JtaAJmcYa3vMSzZMa2"));
		PublicKey publicKey = ed25519.publicKeyFromEncoding(Base58.decode("4HLeNGESjNkHUSURF6rumFdd8CkqabDxCQNmGQhHg99y"));

		return new KeyPair(publicKey, privateKey);
	}
}