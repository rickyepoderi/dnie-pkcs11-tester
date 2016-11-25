/*
 * Copyright (c) 2016 ricky <https://github.com/rickyepoderi/dnie-pkcs11-tester>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <termios.h>
#include <getopt.h>
#include <sys/wait.h>
#include <openssl/x509.h>

#define KWHT  "\x1B[37m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KNRM  "\x1B[0m"

/* HELPER FUNCTIONS */

void error(int print_pid, const char *format, ...) {
  va_list arglist;
  printf("%s", KRED);
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  if (print_pid) {
    printf(" (%d)%s\n", getpid(), KNRM);
  } else {
    printf("%s\n", KNRM);
  }
}

void message(int print_pid, const char *format, ...) {
  va_list arglist;
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  if (print_pid) {
    printf(" (%d)\n", getpid());
  } else {
    printf("%s\n", KNRM);
  }
}

void information(int print_pid, const char *format, ...) {
  va_list arglist;
  printf("%s", KGRN);
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  if (print_pid) {
    printf(" (%d)%s\n", getpid(), KNRM);
  } else {
    printf("%s\n", KNRM);
  }
}

char* log_session_info_state(CK_STATE s) {
  switch(s) {
    case CKS_RO_PUBLIC_SESSION: return "CKS_RO_PUBLIC_SESSION";
    case CKS_RO_USER_FUNCTIONS: return "CKS_RO_USER_FUNCTIONS";
    case CKS_RW_PUBLIC_SESSION: return "CKS_RW_PUBLIC_SESSION";
    case CKS_RW_USER_FUNCTIONS: return "CKS_RW_USER_FUNCTIONS";
    case CKS_RW_SO_FUNCTIONS: return "CKS_RW_SO_FUNCTIONS";
  }
}

char* log_pkcs11_error_name(CK_RV rv) {
  switch(rv) {
    case CKR_OK: return "CKR_OK";
    case CKR_CANCEL: return "CKR_CANCEL";
    case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
    case CKR_NO_EVENT: return "CKR_NO_EVENT";
    case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
    case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
    case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
    case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
    case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
    case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
    case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
    case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
    case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
    case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
    case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
    case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
    case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
    case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
    case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
    case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
    case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
    case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
    case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
    case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
    case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
    case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
    case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
    case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
    case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
    case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
    case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
    case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
    case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
    case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
    case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
    case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
    case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
    case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
    case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
    case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
    default:
      return "Unknown CKR error";
  }
}

void CHECK_RV(CK_RV rv, const char* function) {
  if (rv != CKR_OK) { 
    error(0, "Error in %s [%s]\n", function, log_pkcs11_error_name(rv));
    exit(1);
  }
}

char* class_to_string(CK_OBJECT_CLASS class) {
  switch (class) {
    case CKO_DATA:
      return "data object";
    case CKO_CERTIFICATE:
      return "certificate";
    case CKO_PUBLIC_KEY:
      return "public key";
    case CKO_PRIVATE_KEY:
      return "private key";
    case CKO_SECRET_KEY:
      return "secret key";
    case CKO_HW_FEATURE:
      return "hardware feature";
    case CKO_DOMAIN_PARAMETERS:
      return "domain parameters";
    case CKO_VENDOR_DEFINED:
      return "vendor defined";
    default:
      return "unknown";
  }
}

void request_password(char* password, int password_len) {
  struct termios oflags, nflags;

  // disabling echo
  tcgetattr(fileno(stdin), &oflags);
  nflags = oflags;
  nflags.c_lflag &= ~ECHO;
  nflags.c_lflag |= ECHONL;

  if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
    error(0, "tcsetattr");
    exit(1);
  }

  printf("password: ");
  fgets(password, password_len, stdin);
  password[strlen(password) - 1] = 0;

  // restore terminal
  if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
    error(0, "tcsetattr");
    exit(1);
  }
}

/* GLOVAL VARS */

int slot = -1;

int check_dnie_inserted() {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 0;
  CK_SLOT_INFO info_slot;
  CK_SLOT_ID slots[128];
  CK_TOKEN_INFO info_token;

  information(0, "Starting check_dnie_inserted...", "ssd");
  CHECK_RV(C_Initialize(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, NULL_PTR, &num_slots), "C_GetSlotList");
  if (num_slots == 0) {
    error(0, "No slots available in the system");
    return 1;
  } else if (num_slots > 128) {
    error(0, "Too many slots, only 128 are managed");
    return 1;
  } else {
    message(0, "  Found %d slots...", num_slots);
  }
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  for (int i = 0; i < num_slots; i++) {
    CHECK_RV(functions->C_GetSlotInfo(slots[i], &info_slot), "C_GetSlotInfo");
    message(0, "  Found slot: %d - \"%s\"", i, info_slot.slotDescription);
    CHECK_RV(functions->C_GetTokenInfo(slots[i], &info_token), "C_GetTokenInfo");
    message(0, "  Found token: \"%s\"", info_token.label);
    if (strstr(info_token.label, "DNI electrónico") != NULL) {
      slot = i;
      break;
    }
  }
  C_Finalize(NULL_PTR);
  if (slot != -1) {
      information(0, "Found DNIe at slot %d", slot);
      return 0;
  } else {
      error(0, "No DNIe card found");
      return 1;
  }
}

int check_login(char* password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_SESSION_INFO info_session;

  information(0, "Starting check_login...", "ssd");
  CHECK_RV(C_Initialize(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Login(session, CKU_USER, password, strlen(password)), "C_Login");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize(NULL_PTR);
  if (info_session.state == CKS_RW_USER_FUNCTIONS) {
    information(0, "login OK");
  } else {
    error(0, "Invalid session state");
  }
  return 0;
}

#define MAX_OBJECTS 128
#define MAX_BUFFER_SIZE 2048

int read_certificate_value(CK_FUNCTION_LIST_PTR functions, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
    CK_BYTE* buffer, CK_ULONG_PTR buffer_len) {
  CK_ATTRIBUTE values[] = {
    {CKA_VALUE, buffer, *buffer_len},
  };
  X509 *x509;
  BIO *o = BIO_new_fp(stdout,BIO_NOCLOSE);

  CHECK_RV(functions->C_GetAttributeValue(session, object, values, 1), "C_GetAttributeValue");
  *buffer_len = values[0].ulValueLen;
  x509 = d2i_X509(NULL, (const unsigned char**) &buffer, (long int) buffer_len);
  if (x509 == NULL) {
    error(0, "Cannot allocate X509 certificate");
    return 1;
  }
  X509_print_ex(o, x509, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
  X509_free(x509);
}

int check_objects(char* password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_BBOOL bool_true = TRUE;
  CK_ATTRIBUTE template[] = {
    {CKA_TOKEN, &bool_true, sizeof(CK_BBOOL)},
  };
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_OBJECT_CLASS class;
  char buffer[MAX_BUFFER_SIZE + 1];
  CK_ATTRIBUTE values[] = {
    {CKA_LABEL, buffer, MAX_BUFFER_SIZE},
    {CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS)},
  };
  CK_BYTE certificate[MAX_BUFFER_SIZE];
  CK_ULONG certificate_len = MAX_BUFFER_SIZE;
  int i;
  int found_auth_priv = 0, found_sign_priv = 0, found_auth_pub = 0, found_sign_pub = 0,
    found_auth_cert = 0, found_sign_cert = 0;

  information(0, "Starting check_objects...", "ssd");
  CHECK_RV(C_Initialize(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_Login(session, CKU_USER, password, strlen(password)), "C_Login");
  CHECK_RV(functions->C_FindObjectsInit(session, template, sizeof(template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
  CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
  message(0, "  Found %d objects in the DNIe", num_objects);
  for (i = 0; i < num_objects; i++) {
    values[0].ulValueLen = MAX_BUFFER_SIZE;
    CHECK_RV(functions->C_GetAttributeValue(session, vector_object[i], values, 2), "C_GetAttributeValue");
    ((char*)values[0].pValue)[values[0].ulValueLen] = '\0';
    message(0, "  %d.- %x: %s, %s", i, vector_object[i], (char*)values[0].pValue, 
      class_to_string(*((CK_OBJECT_CLASS*) values[1].pValue)));
    if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PRIVATE_KEY &&
        strcmp("KprivAutenticacion", (char*)values[0].pValue) == 0) {
      message(0, "  Found the authentication private key");
      found_auth_priv = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PRIVATE_KEY &&
        strcmp("KprivFirmaDigital", (char*)values[0].pValue) == 0) {
      message(0, "  Found the signing private key");
      found_sign_priv = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PUBLIC_KEY &&
        strcmp("CertAutenticacion", (char*)values[0].pValue) == 0) {
      message(0, "  Found the authentication public key");
      found_auth_pub = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PUBLIC_KEY &&
        strcmp("CertFirmaDigital", (char*)values[0].pValue) == 0) {
      message(0, "  Found the signing public key");
      found_sign_pub = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_CERTIFICATE &&
        strcmp("CertAutenticacion", (char*)values[0].pValue) == 0) {
      message(0, "  Found the authentication certificate");
      read_certificate_value(functions, session, vector_object[i], certificate, &certificate_len);
      found_auth_cert = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_CERTIFICATE &&
        strcmp("CertFirmaDigital", (char*)values[0].pValue) == 0) {
      message(0, "  Found the signing certificate");
      read_certificate_value(functions, session, vector_object[i], certificate, &certificate_len);
      found_sign_cert = 1;
    }
  }
  CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");
  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize(NULL_PTR);
  if (!found_sign_priv || !found_sign_pub || !found_sign_cert ||
    !found_auth_priv || !found_auth_pub || !found_auth_cert) {
    error(0, "Some object is not found in the DNIe");
    return 1;
  } else {
    information(0, "check_objects OK");
    return 0;
  }
}

int check_sign_internal(char* password, int times, char* priv_label, char* pub_label,
    unsigned int sleep_start, unsigned int sleep_sign, int print_pid) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  char* data = "something to sign";
  CK_BYTE signature[MAX_BUFFER_SIZE];
  CK_ULONG signature_len = MAX_BUFFER_SIZE;
  CK_BBOOL true = TRUE;
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE sign_template[] = {
    {CKA_TOKEN, &true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &priv_class, sizeof(priv_class)},
    {CKA_LABEL, priv_label, strlen(priv_label)},
  };
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE ver_template[] = {
    {CKA_TOKEN, &true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &pub_class, sizeof(pub_class)},
    {CKA_LABEL, pub_label, strlen(pub_label)},
  };
  int ok = 0;

  information(print_pid, "Starting check_sign with %s...", priv_label);
  if (sleep_start > 0) {
    message(print_pid, "  Sleeping %d seconds before login and sign process", sleep_start);
    sleep(sleep_start);
    message(print_pid, "  Starting the login and sign process");
  }

  CHECK_RV(C_Initialize(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_Login(session, CKU_USER, password, strlen(password)), "C_Login");

  if (sleep_sign > 0) {
    message(print_pid, "  Sleeping %d seconds after login and before sign process", sleep_sign);
    sleep(sleep_sign);
    message(print_pid, "  Starting the sign process");
  }

  for (int i = 0; i < times; i++) {
    CHECK_RV(functions->C_FindObjectsInit(session, sign_template, sizeof(sign_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
    CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");

    if (num_objects == 1) {
      CHECK_RV(functions->C_SignInit(session, &mechanism, vector_object[0]), "C_SignInit");
      CHECK_RV(functions->C_Sign(session, data, strlen(data) + 1, signature, &signature_len), "C_Sign");
      message(print_pid, "  Signature done successfully");
    } else {
      error(print_pid, "No private key found");
    }
    CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");

    CHECK_RV(functions->C_FindObjectsInit(session, ver_template, sizeof(ver_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
    CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
    if (num_objects == 1) {
      CHECK_RV(functions->C_VerifyInit(session, &mechanism, vector_object[0]), "C_VerifySignInit");
      CHECK_RV(functions->C_Verify(session, data, strlen(data) + 1, signature, signature_len), "C_Verify");
      message(print_pid, "  Verification done successfully");
      ok = 1;
    } else {
      error(print_pid, "No public key found");
    }
    CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");
  }

  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize(NULL_PTR);
  if (ok) {
    information(print_pid, "check_sign OK");
    return 0;
  } else {
    return 1;
  }
}

int check_sign(char* password, int times) {
  return check_sign_internal(password, times, "KprivFirmaDigital", "CertFirmaDigital", 0, 0, 0);
}

int check_auth(char* password, int times) {
  return check_sign_internal(password, times, "KprivAutenticacion", "CertAutenticacion", 0, 0, 0);
}

/* No DNIe object can encrypt/decrypt
int read_auth_certificate(CK_FUNCTION_LIST_PTR functions, CK_SESSION_HANDLE session, CK_BYTE* buffer, CK_ULONG_PTR buffer_len) {
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_BBOOL true = TRUE;
  CK_OBJECT_CLASS pub_class = CKO_CERTIFICATE;
  CK_CHAR pub_label[] = "CertAutenticacion";
  CK_ATTRIBUTE enc_template[] = {
    {CKA_TOKEN, &true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &pub_class, sizeof(pub_class)},
    {CKA_LABEL, pub_label, strlen(pub_label)},
  };
  CK_ATTRIBUTE values[] = {
    {CKA_VALUE, buffer, *buffer_len},
  };

  CHECK_RV(functions->C_FindObjectsInit(session, enc_template, sizeof(enc_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
  CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
  if (num_objects == 1) {
    CHECK_RV(functions->C_GetAttributeValue(session, vector_object[0], values, 1), "C_GetAttributeValue");
    *buffer_len = values[0].ulValueLen;
    message(0, "  The certificate was read successfully");
  } else {
    error(0, "No certificate found");
  }
  CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");
}

int check_encrypt(char* password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  char* data = "something to encrypt";
  CK_BYTE encrypted[MAX_BUFFER_SIZE];
  CK_ULONG encrypted_len = MAX_BUFFER_SIZE;
  CK_BYTE certificate[MAX_BUFFER_SIZE];
  CK_ULONG certificate_len = MAX_BUFFER_SIZE;
  X509 *x509;
  EVP_PKEY *pkey;
  RSA *cert_rsa_key;
  unsigned char *p;
  CK_BBOOL true = TRUE;
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_CHAR priv_label[] = "KprivAutenticacion";
  CK_ATTRIBUTE dec_template[] = {
    {CKA_TOKEN, &true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &priv_class, sizeof(priv_class)},
    {CKA_LABEL, priv_label, strlen(priv_label)},
  };
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_BYTE decrypted[MAX_BUFFER_SIZE];
  CK_ULONG decrypted_len;

  information(0, "Starting check_encrypt...");
  CHECK_RV(C_Initialize(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_Login(session, CKU_USER, password, strlen(password)), "C_Login");

  read_auth_certificate(functions, session, certificate, &certificate_len);
  p = certificate;
  x509 = d2i_X509(NULL, &p, certificate_len);
  pkey = X509_get_pubkey(x509);
  cert_rsa_key = EVP_PKEY_get1_RSA(pkey);
  encrypted_len = RSA_public_encrypt(strlen(data) + 1, data, encrypted, cert_rsa_key, RSA_PKCS1_PADDING);
   
  RSA_free(cert_rsa_key);
  EVP_PKEY_free(pkey);
  X509_free(x509);

  CHECK_RV(functions->C_FindObjectsInit(session, dec_template, sizeof(dec_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
  CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
  if (num_objects == 1) {
    CHECK_RV(functions->C_DecryptInit(session, &mechanism, vector_object[0]), "C_DecryptInit");
    CHECK_RV(functions->C_Decrypt(session, encrypted, encrypted_len, decrypted, &decrypted_len), "C_Decrypt");
    message(0, "  Decryption done successfully");
  } else {
    error(0, "No public key found");
  }
  CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");

  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize(NULL_PTR);
}
*/

int check_process_interference(char* password) {
  int return_status;
  int pid;

  information(0, "Starting check_process_interference...");
  pid = fork();
  if (pid == 0) {
    // child starts immediately but waits between login and sign
    exit(check_sign_internal(password, 1, "KprivAutenticacion", "CertAutenticacion", 0, 60, 1));
  } else {
    // parent sleeps before start and then steals the session to the parent
    check_sign_internal(password, 1, "KprivAutenticacion", "CertAutenticacion", 30, 0, 1);
  }
  // only parent gets here
  waitpid(pid, &return_status, 0);
  if (return_status == 0) {
    information(0, "check_process_interference OK");
  }
  return return_status;
}

void usage(const char* format, ...) {
  va_list arglist;

  va_start(arglist, format);
  error(0, format, arglist);
  va_end(arglist);
  message(0, "  Usage: dnie-pkcs11-tester {OPTIONS}");
  message(0, "  OPTIONS");
  message(0, "    --all -a: All tests");
  message(0, "    --inter -i: Interference test");
  message(0, "    --list -l: Login test");
  message(0, "    --objects -o: List objects test");
  message(0, "    --sign -s: Sign test");
  message(0, "    --auth -t: Auth test");
  message(0, "    --times=NUM -m NUM: Times the sign and auth operation are repeated");
  message(0, "                        (default NUM=1)");
  exit(1);
}

#define RUN_CHECK(rv) if (rv != 0) return 1

int main(int argc, char *argv[]) {
  char password[128];
  int c;
  char* endptr;
  int all_flag = 0, login_flag = 0, objects_flag = 0, 
    sign_flag = 0, auth_flag = 0, inter_flag = 0, times = 1;
  static struct option long_options[] = {
    {"all", no_argument, 0, 'a'},
    {"inter", no_argument, 0, 'i'},
    {"list", no_argument, 0, 'l'},
    {"times", required_argument, 0, 'm'},
    {"objects", no_argument, 0, 'o'},
    {"sign", no_argument, 0, 's'},
    {"auth", no_argument, 0, 't'},
    {0, 0, 0, 0}
  };

  while ((c = getopt_long(argc, argv, "ailm:ost", long_options, NULL)) != -1) {
    switch (c) {
      case 'a': all_flag = 1; break;
      case 'i': inter_flag = 1; break;
      case 'l': login_flag = 1; break;
      case 'm': times = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                  usage("Invalid option times");
                }
                break;
      case 'o': objects_flag = 1; break;
      case 's': sign_flag = 1; break;
      case 't': auth_flag = 1; break;
      case '?': usage("");
    }
  }

  if (!all_flag && !login_flag && !objects_flag && !sign_flag && !auth_flag && !inter_flag) {
    usage("One option is compulsory");
  } 
  if (optind < argc) {
    usage("");
  }

  request_password(password, 128);

  RUN_CHECK(check_dnie_inserted());
  if (all_flag || login_flag) {
    RUN_CHECK(check_login(password));
  }
  if (all_flag || objects_flag) {
    RUN_CHECK(check_objects(password));
  }
  if (all_flag || sign_flag) {
    RUN_CHECK(check_sign(password, times));
  }
  if (all_flag || auth_flag) {
    RUN_CHECK(check_auth(password, times));
  }
  if (all_flag || inter_flag) {
    RUN_CHECK(check_process_interference(password));
  }
}
