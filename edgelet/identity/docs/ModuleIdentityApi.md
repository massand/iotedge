# \ModuleIdentityApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_module**](ModuleIdentityApi.md#create_module) | **Post** /identities/aziot/modules | Create module identity
[**delete_module**](ModuleIdentityApi.md#delete_module) | **Delete** /identities/aziot/modules/{module_name} | Delete a module
[**get_module**](ModuleIdentityApi.md#get_module) | **Get** /identities/aziot/modules/{module_name} | Get module details
[**get_modules**](ModuleIdentityApi.md#get_modules) | **Get** /identities/aziot/modules | List modules


# **create_module**
> ::models::IdentityResult create_module(api_version, module)
Create module identity

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **api_version** | **String**| The version of the API. | [default to 2018-06-28]
  **module** | [**IdentitySpec**](IdentitySpec.md)|  | 

### Return type

[**::models::IdentityResult**](IdentityResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_module**
> delete_module(api_version, module_name)
Delete a module

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **api_version** | **String**| The version of the API. | [default to 2018-06-28]
  **module_name** | **String**| The name of the module to delete. (urlencoded) | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_module**
> ::models::IdentityResult get_module(api_version, module_name)
Get module details

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **api_version** | **String**| The version of the API. | [default to 2018-06-28]
  **module_name** | **String**| The name of the module to obtain identity for. (urlencoded) | 

### Return type

[**::models::IdentityResult**](IdentityResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_modules**
> ::models::IdentityList get_modules(api_version)
List modules

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **api_version** | **String**| The version of the API. | [default to 2018-06-28]

### Return type

[**::models::IdentityList**](IdentityList.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

