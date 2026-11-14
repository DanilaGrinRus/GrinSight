/// Optional native contact directory, unavailable for unsupported backends.
abstract interface class CatalogueApi {
  Future<Map<String, dynamic>> catalogueOwnCode();
  Future<Map<String, dynamic>> catalogueSearch(String name);
  Future<void> catalogueAdd(Map<String, dynamic> profile, String name, {required bool identityChecked});
  Future<Map<String, dynamic>> cataloguePublish(String name, {required bool revoked, required bool consentPublic});
}

/// Optional local identity and publication state for the contact directory.
abstract interface class CatalogueIdentityApi {
  Future<Map<String, dynamic>> catalogueIdentity();
}
