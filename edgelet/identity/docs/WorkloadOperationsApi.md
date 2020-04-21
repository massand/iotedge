# \WorkloadOperationsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_current_identity**](WorkloadOperationsApi.md#get_current_identity) | **Get** /identities/aziot/identity | Get primary cloud identity for authenticated workload
[**sign**](WorkloadOperationsApi.md#sign) | **Post** /identities/aziot/identity/sign | Sign using identity keypair (e.g. signing cert credentials)


# **get_current_identity**
> ::models::IdentityResult get_current_identity(api_version)
Get primary cloud identity for authenticated workload

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **api_version** | **String**| The version of the API. | [default to 2018-06-28]

### Return type

[**::models::IdentityResult**](IdentityResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **sign**
> ::models::SignResponse sign(api_version, sign_payload)
Sign using identity keypair (e.g. signing cert credentials)

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **api_version** | **String**| The version of the API. | [default to 2018-06-28]
  **sign_payload** | [**SignRequest**](SignRequest.md)| The data to be signed. | 

### Return type

[**::models::SignResponse**](SignResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

