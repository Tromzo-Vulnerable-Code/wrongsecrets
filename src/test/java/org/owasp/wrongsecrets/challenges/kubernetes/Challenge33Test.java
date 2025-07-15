package org.owasp.wrongsecrets.challenges.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.owasp.wrongsecrets.Challenges.ErrorResponses.DECRYPTION_ERROR;

import org.junit.jupiter.api.Test;

class Challenge33Test {

  private static final String DEFAULT_TEST_SECRET = "if_you_see_this_please_use_k8s";
  private static final String DEFAULT_ENCRYPTION_KEY = "Letsencryptnow!!";
  private static final String ENCRYPTED_TEST_VALUE = "VBUGh3wu/3I1naHj1Uf97Y0Lq8B5/92q1jwp3/aYSwHSJI8WqdZnYLj78hESlfPPKf1ZKPap4z2+r+G9NRwdFU/YBMTY3cNguMm5C6l2pTK9JhPFnUzerIwMrnhu9GjrqSFn/BtOvLnQa/mSgXDNJYUOU8gCHFs9JEeQv9hpWpyxlB2Nqu0MHrPNODY3ZohhkjWXaxbjCZi9SpmHydU06Z7LqWyF39G6V8CF6LBPkdUn3aJAV++F0Q9IcSM=";

  @Test
  void defaultShouldNotDecrypt() {
    var challenge = new Challenge33(DEFAULT_TEST_SECRET, DEFAULT_ENCRYPTION_KEY);
    assertThat(challenge.spoiler().solution()).isNotEmpty();
    assertThat(challenge.answerCorrect(challenge.spoiler().solution())).isTrue();
    assertThat(challenge.spoiler().solution()).isEqualTo(DEFAULT_TEST_SECRET);
  }

  @Test
  void decryptsCypherTextAndSolvesSolution() {
    var challenge = new Challenge33(ENCRYPTED_TEST_VALUE, DEFAULT_ENCRYPTION_KEY);
    assertThat(challenge.spoiler().solution()).isNotEmpty();
    assertThat(challenge.answerCorrect(challenge.spoiler().solution())).isTrue();
    assertThat(challenge.spoiler().solution()).isNotEqualTo(DEFAULT_TEST_SECRET);
  }
  
  @Test
  void decryptFailsWithIncorrectKey() {
    // Test with an incorrect key to verify decryption fails
    String incorrectKey = "WrongEncryption!!";
    var challenge = new Challenge33(ENCRYPTED_TEST_VALUE, incorrectKey);
    
    // Should return error when using wrong key
    assertThat(challenge.spoiler().solution()).isEqualTo(DECRYPTION_ERROR);
    
    // Answer verification should fail
    assertThat(challenge.answerCorrect(challenge.spoiler().solution())).isFalse();
  }

  @Test
  void acceptsConfigurableKey() {
    // Test with a custom encryption key
    String customKey = "CustomSecret12345";
    var challenge = new Challenge33(DEFAULT_TEST_SECRET, customKey);
    
    // Default secret value should still work with any key
    assertThat(challenge.spoiler().solution()).isEqualTo(DEFAULT_TEST_SECRET);
    assertThat(challenge.answerCorrect(challenge.spoiler().solution())).isTrue();
  }
  
  @Test
  void environmentSpecificEncryptionKey() {
    // This test verifies that the challenge accepts an externally configured key
    // which demonstrates the fix for the hardcoded key vulnerability
    String environmentKey = "EnvironmentKey123";
    var challenge = new Challenge33(DEFAULT_TEST_SECRET, environmentKey);
    
    // The challenge should work with environment-specific keys
    assertThat(challenge.spoiler().solution()).isEqualTo(DEFAULT_TEST_SECRET);
    assertThat(challenge.answerCorrect(DEFAULT_TEST_SECRET)).isTrue();
  }
  
  @Test
  void emptyKeyHandledGracefully() {
    // Test with an empty key
    var challenge = new Challenge33(ENCRYPTED_TEST_VALUE, "");
    
    // Should handle empty key gracefully
    assertThat(challenge.spoiler().solution()).isEqualTo(DECRYPTION_ERROR);
  }
}