# \DeviceIdentityApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_api_versions**](DeviceIdentityApi.md#get_api_versions) | **Get** /identities/apiversions | Get supported API versions
[**get_device**](DeviceIdentityApi.md#get_device) | **Get** /identities/aziot/device | Get device
[**reprovision_device**](DeviceIdentityApi.md#reprovision_device) | **Post** /identities/aziot/device/reprovision | Trigger a device reprovisioning flow.


# **get_api_versions**
> ::models::IdentityResult get_api_versions()
Get supported API versions

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**::models::IdentityResult**](IdentityResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_device**
> ::models::IdentityResult get_device(api_version)
Get device

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

# **reprovision_device**
> reprovision_device(api_version)
Trigger a device reprovisioning flow.

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **api_version** | **String**| The version of the API. | [default to 2018-06-28]

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

