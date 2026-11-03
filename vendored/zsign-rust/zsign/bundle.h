#pragma once
#include "common.h"
#include "json.h"
#include "openssl.h"
#include <vector>
#include <map>

class ZBundle
{
public:
	ZBundle();

public:
	bool SignFolder(ZSignAsset* pSignAsset,
					const string& strFolder,
					const string& strBundleId,
					const string& strBundleVersion,
					const string& strDisplayName,
					const vector<string>& arrDylibFiles,
					bool bForce,
					bool bWeakInject,
					bool bEnableCache);

	// SetBundleAsset signs the nested bundle (an app extension) whose
	// CFBundleIdentifier is strBundleId with its own profile and
	// entitlements, and puts that profile in it. Bundles without one are
	// signed with the app's asset, as before.
	void SetBundleAsset(const string& strBundleId, ZSignAsset* pSignAsset);

private:
	ZSignAsset* AssetFor(const string& strBundleId);
	bool WriteBundleProfiles(jvalue& jvRoot);
	bool SignNode(jvalue& jvNode);
	void GetNodeChangedFiles(jvalue& jvNode);
	void GetChangedFiles(jvalue& jvNode, vector<string>& arrChangedFiles);
	bool ModifyPluginsBundleId(const string& strOldBundleId, const string& strNewBundleId);
	bool ModifyBundleInfo(const string& strBundleId, const string& strBundleVersion, const string& strDisplayName);

private:
	bool FindAppFolder(const string& strFolder, string& strAppFolder);
	bool GetObjectsToSign(const string& strFolder, jvalue& jvInfo);
	bool GetSignFolderInfo(const string& strFolder, jvalue& jvNode, bool bGetName = false);

private:
	bool GenerateCodeResources(const string& strFolder, jvalue& jvCodeRes);

private:
	bool			m_bForceSign;
	bool			m_bWeakInject;
	ZSignAsset*		m_pSignAsset;
	vector<string>	m_arrInjectDylibs;
	map<string, ZSignAsset*>	m_mapBundleAssets;

public:
	string			m_strAppFolder;
};
