using Dynamicweb.Core;
using Dynamicweb.DataIntegration.Integration;
using Dynamicweb.DataIntegration.ProviderHelpers;
using Dynamicweb.Logging;
using Dynamicweb.Mailing;
using Dynamicweb.Security.SystemTools;
using Dynamicweb.Security.UserManagement;
using Dynamicweb.Security.UserManagement.Common.SystemFields;
using Dynamicweb.Security.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Mail;
using System.Text;

namespace Dynamicweb.DataIntegration.Providers.UserProvider;

internal class UserDestinationWriter : BaseSqlWriter
{
    private readonly Job _job;
    private readonly SqlConnection _connection;
    private readonly SqlCommand _sqlCommand;
    private readonly bool _removeMissingUsers;
    private readonly bool _deactivateMissingUsers;
    private readonly bool _generateUserPasswords;
    private readonly bool _encryptUserPasswords;
    private readonly UserPasswordHashAlgorithm _userPasswordHashAlgorithm;
    private readonly bool _removeMissingGroups;
    private List<int> _groupsWhereSubGroupsAreImported = new List<int>();
    private readonly bool _removeMissingImpersonation;
    private readonly bool _removeMissingAddresses;
    private bool _useEmailForUsername;
    private readonly bool _deleteOnlyFromGroupsThatAreImportedTo;

    private readonly string _userKeyField;
    private readonly string _mailSubject;
    private readonly string _senderEmail;
    private readonly string _emailTemplate;
    protected internal DataSet DataToWrite = new DataSet();

    private readonly string _GroupUserType = "2";
    private readonly string _UserType = "5";
    private List<string> _groupsWhereUsersAreImported = new List<string>();

    private List<GroupHierarchyItem> GroupHierarchyItemsList;
    private ILogger _logger;
    //sets AccessUserNewsletterAllowed field to true if allowed
    private bool _allowEmail;
    //AccessUserGroupID for import all users to it if it exists
    private readonly string _importGroupID;

    private List<UserPassword> UsersPasswordsToSend;
    private readonly int _passwordLength = 8;
    private string[] SearchingUserColumns = new string[] { "AccessUserID", "AccessUserUserName", "AccessUserCustomerNumber", "AccessUserEmail", "AccessUserExternalId" };
    private SystemFieldCollection SystemFields = SystemField.GetSystemFields("AccessUser");
    protected DuplicateRowsHandler duplicateRowsHandler;
    private bool ImportUsersBelongExactlyImportGroups;
    private List<int> MappingIdsWithAaccessUserGroupsColumn = new List<int>();
    private readonly bool _skipFailingRows;
    internal List<string> UpdatedUsers = new List<string>();
    private List<int> MappingsWithUpdateUsersByCustomerNumberMode = new List<int>();
    private TableCollection _schemaTables = null;

    public UserDestinationWriter(Job job, SqlConnection connection,
        bool removeMissingUsers, bool generateUserPasswords, bool encryptUserPasswords, bool removeMissingGroups, bool UseEmailForUsername,
        string userKeyField, string mailSubject, string senderEmail, string emailTemplate, bool allowEmail, string destinationGroup, bool deleteOnlyFromGroupsThatAreImportedTo, ILogger logger,
        bool discardDuplicates, bool importUsersBelongExactlyImportGroups, bool removeMissingImpersonation, bool removeMissingAddresses, bool deactivateMissingUsers,
        Dictionary<string, string> groupDestinationColumnMapping)
        : this(job, connection, removeMissingUsers, generateUserPasswords, encryptUserPasswords, removeMissingGroups, UseEmailForUsername,
        userKeyField, mailSubject, senderEmail, emailTemplate, allowEmail, destinationGroup, deleteOnlyFromGroupsThatAreImportedTo, logger,
        discardDuplicates, importUsersBelongExactlyImportGroups, removeMissingImpersonation, removeMissingAddresses, deactivateMissingUsers,
        groupDestinationColumnMapping, false)
    {
    }

    public UserDestinationWriter(Job job, SqlConnection connection,
    bool removeMissingUsers, bool generateUserPasswords, bool encryptUserPasswords, bool removeMissingGroups, bool UseEmailForUsername,
    string userKeyField, string mailSubject, string senderEmail, string emailTemplate, bool allowEmail, string destinationGroup, bool deleteOnlyFromGroupsThatAreImportedTo, ILogger logger,
    bool discardDuplicates, bool importUsersBelongExactlyImportGroups, bool removeMissingImpersonation, bool removeMissingAddresses, bool deactivateMissingUsers,
    Dictionary<string, string> groupDestinationColumnMapping, bool skipFailingRows)
    {
        _useEmailForUsername = UseEmailForUsername;
        _removeMissingUsers = removeMissingUsers;
        _deactivateMissingUsers = deactivateMissingUsers;
        _generateUserPasswords = generateUserPasswords;
        _encryptUserPasswords = encryptUserPasswords;
        _removeMissingGroups = removeMissingGroups;
        _removeMissingImpersonation = removeMissingImpersonation;
        _removeMissingAddresses = removeMissingAddresses;
        _userKeyField = userKeyField;
        _mailSubject = mailSubject;
        _senderEmail = senderEmail;
        _emailTemplate = emailTemplate;
        _allowEmail = allowEmail;
        _importGroupID = destinationGroup;
        _deleteOnlyFromGroupsThatAreImportedTo = deleteOnlyFromGroupsThatAreImportedTo;
        _logger = logger;

        _job = job;
        _connection = connection;
        _skipFailingRows = skipFailingRows;
        _schemaTables = _job.Destination.GetSchema().GetTables();

        _sqlCommand = connection.CreateCommand();
        _sqlCommand.CommandTimeout = 3600;
        CheckMappingsUsersByCustomerNumberMode();
        CreateTempTables();

        GroupHierarchyItemsList = new List<GroupHierarchyItem>();
        UsersPasswordsToSend = new List<UserPassword>();

        var hashAlgorithm = UserPasswordHashAlgorithm.MD5;
        Enum.TryParse(Dynamicweb.Configuration.SystemConfiguration.Instance.GetValue("/Globalsettings/Modules/Extranet/EncryptPasswordHash"), out hashAlgorithm);
        _userPasswordHashAlgorithm = hashAlgorithm;

        bool discardDuplicatesFromMapping = false;
        if (!discardDuplicates)
        {
            discardDuplicatesFromMapping = job.Mappings.Where(m => m != null && m.Active).Any(m =>
            {
                bool? v = m.GetOptionValue("DiscardDuplicates");
                return v.HasValue && v.Value;
            });
        }
        if (discardDuplicates || discardDuplicatesFromMapping)
        {
            duplicateRowsHandler = new DuplicateRowsHandler(logger, job.Mappings);
            foreach (Mapping mapping in job.Mappings.Where(m => m.Active && m.GetColumnMappings().Count > 0))
            {
                //add PK columns selected from the job xml to the PK columns from the db list
                List<Column> destinationColumns = duplicateRowsHandler.GetTableKeyColumns(mapping.DestinationTable.Name);
                List<Column> destinationColumnsFromJobXml = mapping.DestinationTable.Columns.Where(c => c != null && c.IsPrimaryKey).ToList();
                if (destinationColumns != null && destinationColumnsFromJobXml != null && destinationColumnsFromJobXml.Count() > 0
                    && !destinationColumns.Any(dc => destinationColumnsFromJobXml.Any(columnFromXml => string.Equals(columnFromXml.Name, dc.Name, StringComparison.InvariantCultureIgnoreCase))))
                {
                    var missedPKColumns = destinationColumnsFromJobXml.Where(c => !destinationColumns.Any(dc => string.Equals(c.Name, dc.Name, StringComparison.InvariantCultureIgnoreCase))).ToList();
                    destinationColumns.AddRange(missedPKColumns);
                }
            }
            List<Column> groupsColumns = duplicateRowsHandler.GetTableKeyColumns("AccessUserGroup");
            if (groupsColumns != null)
            {
                UpdateAccessUserGroupPkColumns(groupsColumns, groupDestinationColumnMapping);
            }
        }
        ImportUsersBelongExactlyImportGroups = importUsersBelongExactlyImportGroups;
        if (connection.State != ConnectionState.Open)
            connection.Open();
    }

    private Hashtable _existingUserGroupIDs;
    private Hashtable ExistingUserGroupIDs
    {
        get
        {
            if (_existingUserGroupIDs == null)
            {
                _existingUserGroupIDs = new Hashtable();
                DataTable table = GetExistingGroupsDataTable();
                if (table != null && table.Rows.Count > 0)
                {
                    string key;
                    foreach (DataRow row in table.Rows)
                    {
                        key = row["AccessUserID"].ToString();
                        if (!_existingUserGroupIDs.ContainsKey(key))
                            _existingUserGroupIDs.Add(key, null);
                    }
                }
            }
            return _existingUserGroupIDs;
        }
    }

    private DataTable _existingGroups;
    private DataTable ExistingGroups
    {
        get
        {
            if (_existingGroups == null)
            {
                _existingGroups = GetExistingGroupsDataTable();
            }
            return _existingGroups;
        }
    }

    private Hashtable _existingUserGroups;
    private Hashtable ExistingUserGroups
    {
        get
        {
            if (_existingUserGroups == null)
            {
                _existingUserGroups = new Hashtable();
                DataTable table = GetExistingGroupsDataTable();
                if (table != null && table.Rows.Count > 0)
                {
                    string key;
                    foreach (DataRow row in table.Rows)
                    {
                        key = row["AccessUserUserName"].ToString();
                        if (!_existingUserGroups.ContainsKey(key))
                            _existingUserGroups.Add(key, row);
                    }
                }
            }
            return _existingUserGroups;

        }
    }

    private DataTable _existingUsers;

    private DataTable ExistingUsers
    {
        get
        {
            if (_existingUsers == null)
            {
                //create the data adapter 
                SqlDataAdapter usersDataAdapter = new SqlDataAdapter("select * from AccessUser", _sqlCommand.Connection);
                if (_sqlCommand.Transaction != null)
                    usersDataAdapter.SelectCommand.Transaction = _sqlCommand.Transaction;
                // create the DataSet 
                new SqlCommandBuilder(usersDataAdapter);
                DataSet dataSet = new DataSet();
                // fill the DataSet using our DataAdapter 
                usersDataAdapter.Fill(dataSet);
                _existingUsers = dataSet.Tables[0];
            }
            return _existingUsers;

        }
    }

    /// <summary>
    /// Returns the column name from AccessUser table for seraching existing users. If no column selected in UserKey Filed,
    /// AccessUserUserName is used
    /// </summary>
    private string ColumnNameForSearchingUsers
    {
        get
        {
            string ret = "Auto";
            if (!string.IsNullOrEmpty(_userKeyField))
            {
                ret = _userKeyField;
            }
            return ret;
        }
    }

    private bool UseAutoSearching
    {
        get
        {
            return string.Compare(ColumnNameForSearchingUsers, "Auto", true) == 0;
        }
    }

    public void CreateTempTable(string tempTableSchema, string tempTableName, string tempTablePrefix, List<SqlColumn> destinationColumns)
    {
        SQLTable.CreateTempTable(_sqlCommand, tempTableSchema, tempTableName, tempTablePrefix, destinationColumns, _logger);
    }

    private void CheckMappingsUsersByCustomerNumberMode()
    {
        foreach (var mapping in _job.Mappings.FindAll(m => m.DestinationTable.Name == "AccessUser"))
        {
            if (mapping != null)
            {
                var cm = mapping.GetColumnMappings();
                if (!_generateUserPasswords && !_encryptUserPasswords && !_useEmailForUsername &&
                    cm.Find(m => m.DestinationColumn.Name == "AccessUserCustomerNumber") != null &&
                    cm.Find(m => m.DestinationColumn.Name == "AccessUserID") == null &&
                    cm.Find(m => m.DestinationColumn.Name == "AccessUserUserName") == null &&
                    cm.Find(m => m.DestinationColumn.Name == "AccessUserEmail") == null)
                {
                    MappingsWithUpdateUsersByCustomerNumberMode.Add(mapping.GetId());
                }
            }
        }
    }

    private bool IsUpdateUsersByCustomerNumberMode(Mapping mapping)
    {
        return MappingsWithUpdateUsersByCustomerNumberMode.Contains(mapping.GetId());
    }


    internal void CreateTempTables()
    {
        foreach (Table table in _schemaTables)
        {
            //enumareate all found mappings with same destination table name and create separate temp table with mapping id
            foreach (var mapping in _job.Mappings.FindAll(m => m.DestinationTable.Name == table.Name))
            {
                if (mapping != null)
                {
                    List<SqlColumn> destColumns = new List<SqlColumn>();
                    if (mapping.DestinationTable.Name == "AccessUser")
                    {
                        Column accessUserGroupscolumn = mapping.DestinationTable.Columns.FirstOrDefault(c => c.Name == "AccessUserGroups");
                        if (accessUserGroupscolumn != null)
                        {
                            //Fix for AccessUserGroups(nvarchar(255)) column in the AccessUserTempTable - increase its size to nvarchar(max)
                            ((SqlColumn)accessUserGroupscolumn).Limit = -1;
                            MappingIdsWithAaccessUserGroupsColumn.Add(mapping.GetId());
                        }
                    }
                    var columnMappings = mapping.GetColumnMappings();
                    foreach (ColumnMapping columnMapping in columnMappings)
                    {
                        destColumns.Add((SqlColumn)columnMapping.DestinationColumn);
                    }
                    switch (mapping.DestinationTable.Name)
                    {
                        case "AccessUser":
                            bool updateUsersByCustomerNumberMode = IsUpdateUsersByCustomerNumberMode(mapping);
                            if (!updateUsersByCustomerNumberMode && UseAutoSearching && columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, "AccessUserID", true) == 0) == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => string.Compare(m.Name, "AccessUserID", true) == 0));
                            }
                            if (!updateUsersByCustomerNumberMode && columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserUserName") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserUserName"));
                            }
                            if (!updateUsersByCustomerNumberMode && columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserPassword") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserPassword"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserActive") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserActive"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserGroups") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserGroups"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserType") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserType"));
                            }
                            if (_allowEmail && columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserNewsletterAllowed") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserNewsletterAllowed"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserCreatedOn") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserCreatedOn"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserUpdatedOn") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserUpdatedOn"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserCreatedBy") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserCreatedBy"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserUpdatedBy") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserUpdatedBy"));
                            }
                            break;
                        case "AccessUserGroup":
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserUserName") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserUserName"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserName") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserName"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserActive") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserActive"));
                            }
                            if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserType") == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => m.Name == "AccessUserType"));
                            }
                            break;
                        case "AccessUserAddress":
                            if (columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, "AccessUserAddressUserID", true) == 0) == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => string.Compare(m.Name, "AccessUserAddressUserID", true) == 0));
                            }
                            break;
                        case "AccessUserSecondaryRelation":
                            if (columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, "AccessUserSecondaryRelationUserID", true) == 0) == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => string.Compare(m.Name, "AccessUserSecondaryRelationUserID", true) == 0));
                            }
                            if (columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, "AccessUserSecondaryRelationSecondaryUserID", true) == 0) == null)
                            {
                                destColumns.Add((SqlColumn)mapping.DestinationTable.Columns.Find(m => string.Compare(m.Name, "AccessUserSecondaryRelationSecondaryUserID", true) == 0));
                            }
                            break;
                        case "SystemFieldValue":
                            SqlColumn SystemFieldValueTableNameColumn = new SqlColumn("SystemFieldValueTableName", "nvarchar", table, -1, false, true);
                            mapping.DestinationTable.Columns.Add(SystemFieldValueTableNameColumn);
                            destColumns.Add(SystemFieldValueTableNameColumn);
                            break;
                    }
                    CreateTempTable(table.SqlSchema, table.Name, $"TempTableForBulkImport{mapping.GetId()}", destColumns);
                    AddTableToDataset(destColumns, GetTableName(table.Name, mapping));
                }
            }
        }
    }

    private string GetTableName(string name, Mapping mapping)
    {
        return $"{name}${mapping.GetId()}";
    }

    private string GetTableNameWithoutPrefix(string name)
    {
        if (name.Contains("$"))
        {
            return name.Split(new char[] { '$' })[0];
        }
        else
        {
            return name;
        }
    }

    private string GetPrefixFromTableName(string name)
    {
        if (name.Contains("$"))
        {
            return name.Split(new char[] { '$' })[1];
        }
        else
        {
            return string.Empty;
        }
    }

    private void AddTableToDataset(IEnumerable<SqlColumn> columns, string tableName)
    {
        var newTable = DataToWrite.Tables.Add(tableName);
        foreach (SqlColumn destColumn in columns)
        {
            newTable.Columns.Add(destColumn.Name, destColumn.Type);
        }
    }

    public void Write(Dictionary<string, object> row, Mapping mapping, bool discardDuplicates)
    {
        DataRow dataRow = DataToWrite.Tables[GetTableName(mapping.DestinationTable.Name, mapping)].NewRow();

        var columnMappings = mapping.GetColumnMappings();
        foreach (ColumnMapping columnMapping in columnMappings.Where(cm => cm.Active))
        {
            object rowValue = null;
            bool hasValueInRow = columnMapping.SourceColumn is not null && row.TryGetValue(columnMapping.SourceColumn?.Name, out rowValue);
            if (columnMapping.HasScriptWithValue || hasValueInRow)
            {
                object evaluatedValue = columnMapping.ConvertInputValueToOutputValue(rowValue);

                if (hasValueInRow)
                {
                    //if some column in source is used two or more times in the mapping and has some ScriptType enabled - skip assigning its value to "row"
                    //it will just be used in "datarow", this is needed for not to erase the values in other mappings with this source column
                    var similarColumnMappings = columnMappings.Where(cm => cm.Active && cm.SourceColumn != null && string.Compare(cm.SourceColumn.Name, columnMapping.SourceColumn.Name, true) == 0);
                    if (similarColumnMappings.Count() == 1)
                    {
                        row[columnMapping.SourceColumn.Name] = evaluatedValue;
                    }
                }
                dataRow[columnMapping.DestinationColumn.Name] = evaluatedValue;
            }
            else
            {
                throw new Exception(GetRowValueNotFoundMessage(row, columnMapping.SourceColumn?.Table?.Name ?? columnMapping.DestinationColumn?.Table?.Name,
                    columnMapping.SourceColumn?.Name ?? columnMapping.DestinationColumn?.Name));
            }
        }

        switch (mapping.DestinationTable.Name)
        {
            case "AccessUser":
                bool updateUsersByCustomerNumberMode = IsUpdateUsersByCustomerNumberMode(mapping);
                if (!UseAutoSearching && (columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, ColumnNameForSearchingUsers, true) == 0) == null ||
                    !columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, ColumnNameForSearchingUsers, true) == 0).Active))
                {
                    throw new Exception(string.Format("User key field: '{0}' must be included in the mapping.", ColumnNameForSearchingUsers));
                }
                DataRow existingUser = updateUsersByCustomerNumberMode ? null : GetExistingUser(row, mapping);
                if (existingUser != null)
                {
                    if (UseAutoSearching && columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, "AccessUserID", true) == 0) == null)
                    {
                        dataRow["AccessUserID"] = existingUser["AccessUserID"];
                    }
                    UpdatedUsers.Add(Converter.ToString(existingUser["AccessUserID"]));
                }
                if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserActive") == null)
                {
                    dataRow["AccessUserActive"] = (existingUser != null) ? existingUser["AccessUserActive"] : true;
                }
                if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserType") == null)
                {
                    dataRow["AccessUserType"] = (existingUser != null) ? existingUser["AccessUserType"] : _UserType;
                }
                if (!updateUsersByCustomerNumberMode)
                {
                    //if no source column is mapped to accessUserUserName in destination
                    if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserUserName") == null)
                    {
                        if (existingUser != null && !string.IsNullOrWhiteSpace(Converter.ToString(existingUser["AccessUserUserName"])))
                        {
                            dataRow["AccessUserUserName"] = existingUser["AccessUserUserName"];
                        }
                        else if (_useEmailForUsername)
                        {
                            ColumnMapping cm = columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserEmail");
                            if (cm != null)
                            {
                                dataRow["AccessUserUserName"] = GetValue(cm, row);
                            }
                        }
                    }
                    else
                    {
                        if (_useEmailForUsername)
                        {
                            ColumnMapping cm = columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserEmail");
                            if (cm != null)
                            {
                                var accessUserUserName = GetValue(cm, row);
                                if (!string.IsNullOrEmpty(accessUserUserName))
                                {
                                    dataRow["AccessUserUserName"] = accessUserUserName;
                                }
                            }
                        }
                    }
                    if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserPassword") == null && existingUser != null)
                    {
                        dataRow["AccessUserPassword"] = existingUser["AccessUserPassword"];
                    }

                    string password = string.Empty;
                    //the user is being imported for the first time, and no mapping for the password column is set, 
                    //the user is being imported for the first time, there is a mapping, and the input is either NULL or ""                    
                    var pcm = columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserPassword");
                    bool isPasswordPresentInSource = pcm != null &&
                        !string.IsNullOrEmpty(GetValue(pcm, row));
                    if (isPasswordPresentInSource)
                    {
                        password = GetValue(pcm, row);
                        if (_encryptUserPasswords)
                        {
                            string encryptedPassword = encryptedPassword = Crypto.EncryptPassword(password, _userPasswordHashAlgorithm);
                            dataRow["AccessUserPassword"] = encryptedPassword;
                        }
                    }
                    else if (_generateUserPasswords)
                    {
                        if (existingUser == null ||
                            string.IsNullOrEmpty(Converter.ToString(existingUser["AccessUserPassword"])))
                        {
                            //handle password generation
                            password = PasswordGenerator.GeneratePassword(_passwordLength);
                            string encryptedPassword = password;
                            if (_encryptUserPasswords)
                            {
                                encryptedPassword = Crypto.EncryptPassword(password, _userPasswordHashAlgorithm);
                            }
                            dataRow["AccessUserPassword"] = _encryptUserPasswords ? encryptedPassword : password;
                        }
                    }
                    if (!string.IsNullOrEmpty(password) &&
                        (existingUser == null ||
                        string.IsNullOrEmpty(Converter.ToString(existingUser["AccessUserPassword"]))))
                    {
                        string name = null;
                        var cm = columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserName");
                        if (cm != null)
                            name = GetValue(cm, row);
                        string userName = null;
                        cm = columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserUserName");
                        if (cm != null)
                            userName = GetValue(cm, row);
                        var emailMapping = columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserEmail");
                        if (emailMapping != null && Converter.ToBoolean(dataRow["AccessUserActive"]) == true)
                        {
                            string email = GetValue(emailMapping, row);
                            UserPassword userPasswordData = new UserPassword(userName, name, password, email);
                            var countryMapping = columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserCountry");
                            if (countryMapping != null)
                            {
                                userPasswordData.Country = GetValue(countryMapping, row);
                            }
                            UsersPasswordsToSend.Add(userPasswordData);
                        }
                    }
                }
                if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserGroups") == null && existingUser != null && !_deleteOnlyFromGroupsThatAreImportedTo)
                {
                    string userGroups = Converter.ToString(existingUser["AccessUserGroups"]);
                    if (!string.IsNullOrEmpty(userGroups))
                    {
                        userGroups = userGroups.Trim(new char[] { '@' }).Replace("@@", ",");
                    }
                    dataRow["AccessUserGroups"] = userGroups;
                }
                if (_allowEmail && columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserNewsletterAllowed") == null && existingUser != null)
                {
                    dataRow["AccessUserNewsletterAllowed"] = existingUser["AccessUserNewsletterAllowed"];
                }
                //handle User update fields
                dataRow["AccessUserCreatedOn"] = existingUser != null ? existingUser["AccessUserCreatedOn"] : DateTime.Now;
                dataRow["AccessUserUpdatedOn"] = DateTime.Now;
                dataRow["AccessUserCreatedBy"] = existingUser != null ? existingUser["AccessUserCreatedBy"] : User.ImportedUserID;
                dataRow["AccessUserUpdatedBy"] = User.ImportedUserID;
                break;
            case "AccessUserGroup":
                string groupName = string.Empty;
                var accessUserNameMapping = columnMappings.FirstOrDefault(m => m.Active && m.DestinationColumn.Name == "AccessUserName");
                var accessUserUserNameMapping = columnMappings.FirstOrDefault(m => m.Active && m.DestinationColumn.Name == "AccessUserUserName");
                if (accessUserNameMapping == null && accessUserUserNameMapping != null)
                {
                    groupName = GetValue(accessUserUserNameMapping, row).Trim();
                    dataRow["AccessUserUserName"] = groupName;
                    dataRow["AccessUserName"] = groupName;//AccessUserName field should be the same as AccessUserUserName
                }
                else if (accessUserUserNameMapping == null && accessUserNameMapping != null)
                {
                    groupName = GetValue(accessUserNameMapping, row).Trim();
                    dataRow["AccessUserName"] = groupName;
                    dataRow["AccessUserUserName"] = groupName;//AccessUserUserName field should be the same as AccessUserName
                }

                if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserActive") == null)
                {
                    dataRow["AccessUserActive"] = true;
                }
                if (columnMappings.Find(m => m.DestinationColumn.Name == "AccessUserType") == null)
                {
                    //Handle GroupType: If it is not existing group - import with AccessType = 2
                    if (!string.IsNullOrEmpty(groupName) && ExistingUserGroups.ContainsKey(groupName))
                    {
                        dataRow["AccessUserType"] = ((DataRow)ExistingUserGroups[groupName])["AccessUserType"];
                    }
                    else
                    {
                        dataRow["AccessUserType"] = _GroupUserType;
                    }
                }
                if (columnMappings.Find(cm => string.Equals(cm.DestinationColumn.Name, "AccessUserParentID", StringComparison.OrdinalIgnoreCase)) != null &&
                        dataRow["AccessUserParentID"] != DBNull.Value)
                {
                    string parentGroupIDValue = (string)dataRow["AccessUserParentID"];
                    int groupId = Converter.ToInt32(parentGroupIDValue);
                    //Look for existing groups by Parent ID
                    bool isExistingGroup = groupId > 0 && ExistingUserGroupIDs.ContainsKey(parentGroupIDValue);

                    if (!isExistingGroup)
                    {
                        //Look for existing groups by Parent Name
                        if (!string.IsNullOrEmpty(parentGroupIDValue) && ExistingUserGroups.ContainsKey(parentGroupIDValue))
                        {
                            groupId = (int)((DataRow)ExistingUserGroups[parentGroupIDValue])["AccessUserID"];
                            dataRow["AccessUserParentID"] = groupId.ToString();
                        }
                        else
                        {
                            //In this case it is Non existing group, or Group with empty ParentGroup(root group)
                            //Fill HierarchyItems list with GroupName/ParentGroupName - to search by name after Group Insert
                            if (!string.IsNullOrEmpty(parentGroupIDValue) && !string.IsNullOrEmpty(groupName) &&
                                // Avoid circular reference
                                !string.Equals(parentGroupIDValue, groupName))
                            {
                                GroupHierarchyItemsList.Add(new GroupHierarchyItem(groupName, parentGroupIDValue));
                            }
                            //fill the ParentGroupId value with 0 as this is a value by default, it will be filled with different value after group import
                            dataRow["AccessUserParentID"] = "0";
                        }
                    }
                    if (_removeMissingGroups && groupId > 0)
                    {
                        _groupsWhereSubGroupsAreImported.Add(groupId);
                    }
                }
                break;
            case "SystemFieldValue":
                var fieldValueSystemName = GetValue(columnMappings.Find(cm => string.Compare(cm.DestinationColumn.Name, "SystemFieldValueSystemName", true) == 0), row);
                if (!string.IsNullOrEmpty(fieldValueSystemName) && !SystemFields.Any(sf => string.Compare(sf.SystemName, fieldValueSystemName, true) == 0))
                {
                    _logger.Log(string.Format("Can't find the '{0}' in the user system fields. Skipped row: '{1}'.", fieldValueSystemName, BaseProvider.GetFailedSourceRowMessage(row)));
                    return;
                }
                dataRow["SystemFieldValueTableName"] = "AccessUser";
                break;
        }

        //UserImport add-in functionality
        if (mapping.DestinationTable.Name == "AccessUser" && (_allowEmail || !string.IsNullOrEmpty(_importGroupID)))
        {
            if (_allowEmail)
            {
                dataRow["AccessUserNewsletterAllowed"] = true;
            }
            if (!string.IsNullOrEmpty(_importGroupID))
            {
                if (dataRow["AccessUserGroups"] == DBNull.Value || dataRow["AccessUserGroups"] == null || string.IsNullOrEmpty((string)dataRow["AccessUserGroups"]))
                {
                    dataRow["AccessUserGroups"] = _importGroupID;
                }
                else
                {
                    dataRow["AccessUserGroups"] = (string)dataRow["AccessUserGroups"] + "," + _importGroupID;
                }
            }
        }

        if (!discardDuplicates || !duplicateRowsHandler.IsRowDuplicate(columnMappings, mapping, dataRow, row))
        {
            DataToWrite.Tables[GetTableName(mapping.DestinationTable.Name, mapping)].Rows.Add(dataRow);
        }
    }

    public void FinishWriting()
    {
        foreach (DataTable table in DataToWrite.Tables)
        {
            if (GetTableNameWithoutPrefix(table.TableName) != "AccessUserSecondaryRelation" && GetTableNameWithoutPrefix(table.TableName) != "SystemFieldValue")
            {
                BulkCopyTable(table, null);
            }
        }
    }

    private void BulkCopyTable(DataTable table, SqlTransaction transaction)
    {
        using (SqlBulkCopy sqlBulkCopier = (transaction != null) ? new SqlBulkCopy(_connection, SqlBulkCopyOptions.Default, transaction) : new SqlBulkCopy(_connection))
        {
            sqlBulkCopier.DestinationTableName = GetTableNameWithoutPrefix(table.TableName) + "TempTableForBulkImport" + GetPrefixFromTableName(table.TableName);
            sqlBulkCopier.BulkCopyTimeout = 0;
            try
            {
                sqlBulkCopier.WriteToServer(table);
            }
            catch
            {
                string errors = BulkCopyHelper.GetBulkCopyFailures(sqlBulkCopier, table);
                if (_skipFailingRows)
                {
                    int skippedFailedRowsCount = errors.Split(new string[] { System.Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries).Length - 1;
                    skippedFailedRowsCount = skippedFailedRowsCount < 0 ? 0 : skippedFailedRowsCount;
                    if (skippedFailedRowsCount > 0)
                    {
                        _logger.Log($"Skipped {skippedFailedRowsCount} failed rows from the temporary {GetTableNameWithoutPrefix(table.TableName)} table");
                    }
                }
                else
                {
                    throw new Exception(errors);
                }
            }
        }
    }

    public void DeleteExcessFromMainTable(SqlTransaction transaction)
    {
        _sqlCommand.Transaction = transaction;

        foreach (Mapping mapping in _job.Mappings)
        {
            if (mapping.DestinationTable.Name == "AccessUser" && (_removeMissingUsers || _deactivateMissingUsers))
            {
                string extraConditions = " and ([AccessUserType] = 5 or [AccessUserType] = 15)";

                if (_deleteOnlyFromGroupsThatAreImportedTo && _groupsWhereUsersAreImported.Count > 0)
                {
                    string groupCondition = "";
                    foreach (string id in _groupsWhereUsersAreImported)
                    {
                        if (!string.IsNullOrEmpty(groupCondition))
                        {
                            groupCondition += string.Format(" or AccessUserGroups like '%@{0}@%' ", id);
                        }
                        else
                        {
                            groupCondition = string.Format(" AccessUserGroups like '%@{0}@%' ", id);
                        }
                    }
                    extraConditions += " and (" + groupCondition + ")";
                }
                else
                {
                    if (!string.IsNullOrEmpty(_importGroupID))
                    {
                        extraConditions = " and ([AccessUserType] = 5 or [AccessUserType] = 15) and AccessUserGroups = '@" + _importGroupID + "@' ";
                    }
                }
                DeleteExcessFromMainTable(mapping, extraConditions, _sqlCommand, _deactivateMissingUsers);
            }

            if (mapping.DestinationTable.Name == "AccessUserGroup" && _removeMissingGroups)
            {
                string extraConditions = " and ([AccessUserType] IN (2,11) and AccessUserUserName <> 'All extranet users' and AccessUserUserName <> 'All users')";
                DeleteExcessFromMainTable(mapping, extraConditions, _sqlCommand, false);
            }
            if ((mapping.DestinationTable.Name == "AccessUserSecondaryRelation" && _removeMissingImpersonation) ||
                (mapping.DestinationTable.Name == "AccessUserAddress" && _removeMissingAddresses))
            {
                DeleteExcessFromMainTable(mapping, string.Empty, _sqlCommand, false);
            }
        }
    }

    private void DeleteExcessFromMainTable(Mapping mapping, string extraConditions, SqlCommand sqlCommand, bool deactivate)
    {
        StringBuilder sqlClean = new StringBuilder();

        string destinationTableName = mapping.DestinationTable.Name;
        string tempTableName = destinationTableName;
        if (mapping.DestinationTable.Name == "AccessUserGroup")
        {
            //Groups should be deleted from the same table as Users - AccessUser from AccessUserGroup temp table
            destinationTableName = "AccessUser";
            tempTableName = "AccessUserGroup";

            if (_removeMissingGroups && _groupsWhereSubGroupsAreImported.Any())
            {
                // Find sub groups that needs to be deleted from the parent groups
                sqlClean.Append(
                    " WITH users AS ( " +
                    $" SELECT [AccessUserId], [AccessUserParentId] FROM [AccessUser] WHERE [AccessUserParentId] = 0 and AccessUserType IN (2,11) and [AccessUserId] in ({string.Join(",", _groupsWhereSubGroupsAreImported.Distinct())}) " +
                    " UNION ALL " +
                    " SELECT c.[AccessUserId], c.[AccessUserParentId] FROM [AccessUser] c INNER JOIN users u ON c.[AccessUserParentId] = u.[AccessUserId]  WHERE c.[AccessUserType] IN (2,11) " +
                    ") ");
                extraConditions += " and [AccessUserParentId] in (SELECT [AccessUserId] FROM users) ";
            }
        }

        try
        {
            if (deactivate &&
                string.Compare(mapping.DestinationTable.Name, "AccessUser", StringComparison.OrdinalIgnoreCase) == 0)
            {
                sqlClean.Append($"UPDATE [AccessUser] SET AccessUserActive = 0");
            }
            else
            {
                sqlClean.Append($"DELETE FROM [{mapping.DestinationTable.SqlSchema}].[{destinationTableName}]");
            }
            sqlClean.Append($" WHERE NOT EXISTS  (SELECT * FROM [{mapping.DestinationTable.SqlSchema}].[{tempTableName}TempTableForBulkImport{mapping.GetId()}] where ");

            var columnMappings = mapping.GetColumnMappings();
            bool isPrimaryKeyColumnExists = columnMappings.IsKeyColumnExists();
            foreach (ColumnMapping columnMapping in columnMappings)
            {
                if (columnMapping.Active)
                {
                    SqlColumn column = (SqlColumn)columnMapping.DestinationColumn;
                    if (column.IsKeyColumn(columnMappings) || !isPrimaryKeyColumnExists)
                    {
                        sqlClean.Append($"[{mapping.DestinationTable.SqlSchema}].[{destinationTableName}].[{column.Name}]=[{column.Name}] AND ");
                    }
                }
            }
            sqlClean.Remove(sqlClean.Length - 4, 4);
            sqlClean.Append(")");
            if (extraConditions.Length > 0)
            {
                sqlClean.Append(extraConditions);
            }
            List<SqlParameter> parameters = new List<SqlParameter>();
            string mappingConditions = MappingExtensions.GetConditionalsSql(out parameters, mapping.Conditionals, true, true);
            if (!string.IsNullOrEmpty(mappingConditions))
            {
                mappingConditions = mappingConditions.Substring(0, mappingConditions.Length - 4);
                sqlClean.AppendFormat(" AND ( {0} ) ", mappingConditions);
                sqlCommand.Parameters.Clear();
                foreach (SqlParameter p in parameters)
                    sqlCommand.Parameters.Add(p);
            }

            sqlCommand.CommandText = sqlClean.ToString();
            var rowsAffected = sqlCommand.ExecuteNonQuery();
            RowsAffected += rowsAffected;
            if (rowsAffected > 0)
                _logger.Log($"The number of deleted rows: {rowsAffected} for the destination {mapping.DestinationTable.Name} table mapping");
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to remove rows from Table [" + mapping.DestinationTable.SqlSchema + "." + destinationTableName +
                "] that where not present in source. Exception: " + ex.Message + " Sql query: " + sqlCommand.CommandText, ex);
        }
    }

    public void MoveDataToMainTables(SqlTransaction sqlTransaction)
    {
        _sqlCommand.Transaction = sqlTransaction;
        //Add mappings that are missing but needs to be there - EcomGroups & EcomVariantGroups.
        AddMappingsToJobThatNeedsToBeThereForMoveToMainTables();
        //Remove column mappings that shouldn't be included in move
        RemoveColumnMappingsFromJobThatShouldBeSkippedInMoveToMainTables();
        //Do Move for each mapped table
        foreach (Mapping mapping in _job.Mappings)
        {
            var columnMappings = mapping.GetColumnMappings();
            if (mapping.Active && columnMappings.Count > 0)
            {
                if (mapping.DestinationTable.Name == "AccessUserAddress" && DataToWrite.Tables[GetTableName("AccessUserAddress", mapping)] != null)
                {
                    //update AccessUserAddressUserID before inserting to main table
                    UpdateUserAddressesBeforeMoveToMainTable(sqlTransaction, mapping);
                }
                if (mapping.DestinationTable.Name == "AccessUserSecondaryRelation" && DataToWrite.Tables[GetTableName("AccessUserSecondaryRelation", mapping)] != null)
                {
                    UpdateUserSecondaryRelationBeforeMoveToMainTable(sqlTransaction, mapping);
                }
                if (mapping.DestinationTable.Name == "SystemFieldValue" && DataToWrite.Tables[GetTableName("SystemFieldValue", mapping)] != null)
                {
                    UpdateSystemFieldValueBeforeMoveToMainTable(sqlTransaction, mapping);
                }

                MoveDataToMainTable(mapping, sqlTransaction);

                if (mapping.DestinationTable.Name == "AccessUserGroup" &&
                    columnMappings.Find(cm => string.Compare(cm.DestinationColumn.Name, "AccessUserParentID", true) == 0) != null)
                {
                    UpdateGroupHierarchy(sqlTransaction);
                }

                if (mapping.DestinationTable.Name == "AccessUser" && DataToWrite.Tables[GetTableName("AccessUser", mapping)] != null)
                {
                    UpdateUserGroupRelations(sqlTransaction, mapping);
                }
            }
        }
    }

    private bool HasData(string tableName)
    {
        foreach (DataTable table in DataToWrite.Tables)
        {
            if (table.TableName.StartsWith(tableName) && table.Rows.Count > 0)
            {
                return true;
            }
        }
        return false;
    }

    private void AddMappingsToJobThatNeedsToBeThereForMoveToMainTables()
    {
        //Source columns are irrelevant, but must be set, so they are set to a random column
        var randomColumn = _job.Source.GetSchema().GetTables().First(obj => obj.Columns.Count > 0).Columns.First();
        if (HasData("AccessUser"))
        {
            foreach (Mapping accessUserMapping in _job.Mappings.FindAll(m => m.DestinationTable.Name == "AccessUser"))
            {
                if (accessUserMapping != null)
                {
                    bool updateUsersByCustomerNumberMode = IsUpdateUsersByCustomerNumberMode(accessUserMapping);
                    var accessUserColumnMappings = accessUserMapping.GetColumnMappings();
                    if (!updateUsersByCustomerNumberMode && accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserUserName") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserUserName"), false);
                    }
                    if (!updateUsersByCustomerNumberMode && accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserPassword") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserPassword"), false);
                    }
                    if (accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserActive") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserActive"), false);
                    }
                    if (accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserType") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserType"), false);
                    }
                    if (_allowEmail && accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserNewsletterAllowed") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserNewsletterAllowed"), false);
                    }
                    if (!string.IsNullOrEmpty(_importGroupID))
                    {
                        accessUserMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserGroups"), false);
                    }
                    if (accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserCreatedOn") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn, _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserCreatedOn"), false);
                    }
                    if (accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserUpdatedOn") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn, _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserUpdatedOn"), false);
                    }
                    if (accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserCreatedBy") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn, _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserCreatedBy"), false);
                    }
                    if (accessUserColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserUpdatedBy") == null)
                    {
                        accessUserMapping.AddMapping(randomColumn, _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserUpdatedBy"), false);
                    }
                }
            }
        }
        if (HasData("AccessUserGroup"))
        {
            foreach (Mapping groupMapping in _job.Mappings.FindAll(m => m.DestinationTable.Name == "AccessUserGroup"))
            {
                if (groupMapping != null)
                {
                    var groupColumnMappings = groupMapping.GetColumnMappings();
                    if (groupColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserUserName") == null)
                    {
                        groupMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserUserName"), false);
                    }
                    if (groupColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserName") == null)
                    {
                        groupMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserName"), false);
                    }
                    if (groupColumnMappings.Find(cm => cm.DestinationColumn.Name == "AccessUserActive") == null)
                    {
                        groupMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserActive"), false);
                    }
                    var userTypeMapping = groupColumnMappings.Find(cm => cm.Active && cm.DestinationColumn.Name == "AccessUserType");
                    if (userTypeMapping is null)
                    {
                        groupMapping.AddMapping(randomColumn,
                            _schemaTables.Find(t => t.Name == "AccessUser").Columns.Find(c => c.Name == "AccessUserType"), groupColumnMappings.IsKeyColumnExists());
                    }                    
                }
            }
        }
        if (HasData("SystemFieldValue"))
        {
            foreach (Mapping mapping in _job.Mappings.FindAll(m => m.DestinationTable.Name == "SystemFieldValue"))
            {
                if (mapping != null)
                {
                    mapping.AddMapping(randomColumn, _schemaTables.Find(t => t.Name == "SystemFieldValue").Columns.Find(c => c.Name == "SystemFieldValueTableName"), false);
                }
            }
        }
    }
    private void RemoveColumnMappingsFromJobThatShouldBeSkippedInMoveToMainTables()
    {
        foreach (Mapping cleanMapping in _job.Mappings.FindAll(m => m.DestinationTable.Name == "AccessUser"))
        {
            if (cleanMapping != null)
            {
                ColumnMappingCollection columnMapping = cleanMapping.GetColumnMappings(true);
                columnMapping.RemoveAll(cm => cm.DestinationColumn != null && cm.DestinationColumn.Name == "AccessUserGroups");
            }
        }
    }

    private void MoveDataToMainTable(Mapping mapping, SqlTransaction sqlTransaction)
    {
        _sqlCommand.Transaction = sqlTransaction;

        string destinationTableName = mapping.DestinationTable.Name;
        string tempTableName = destinationTableName;
        bool isGroupImport = mapping.DestinationTable.Name == "AccessUserGroup";
        if (isGroupImport)
        {
            //Groups should be imported to the same table as Users - AccessUser from AccessUserGroup temp table
            destinationTableName = "AccessUser";
            tempTableName = "AccessUserGroup";
        }

        List<string> insertColumns = new List<string>();
        try
        {
            List<string> sqlConditionsColumns = new List<string>();
            string firstKey = "";
            var columnMappings = mapping.GetColumnMappings();
            bool isPrimaryKeyColumnExists = columnMappings.IsKeyColumnExists();
            string tempTableAlias = $"[{mapping.DestinationTable.SqlSchema}].[{tempTableName}TempTableForBulkImport{mapping.GetId()}]";

            if (UseAutoSearching && !isPrimaryKeyColumnExists && mapping.DestinationTable.Name != "AccessUserGroup" && mapping.DestinationTable.Name != "AccessUserAddress")
            {
                sqlConditionsColumns.Add("AccessUserId");
                firstKey = "AccessUserID";
            }
            else
            {
                foreach (ColumnMapping columnMapping in columnMappings)
                {
                    if (columnMapping.Active)
                    {
                        SqlColumn column = (SqlColumn)columnMapping.DestinationColumn;
                        if (column.IsKeyColumn(columnMappings) || (!isPrimaryKeyColumnExists && !columnMapping.ScriptValueForInsert))
                        {
                            sqlConditionsColumns.Add(columnMapping.DestinationColumn.Name);

                            if (firstKey == "")
                                firstKey = columnMapping.DestinationColumn.Name;
                        }
                    }
                }
            }

            var updateColumnList = new List<string>();
            var insertSelectList = new List<string>();

            foreach (ColumnMapping columnMapping in columnMappings)
            {
                if (columnMapping.Active)
                {
                    insertColumns.Add("[" + columnMapping.DestinationColumn.Name + "]");
                    if (!((SqlColumn)columnMapping.DestinationColumn).IsIdentity && !((SqlColumn)columnMapping.DestinationColumn).IsKeyColumn(columnMappings) && !columnMapping.ScriptValueForInsert)
                        updateColumnList.Add($"[{columnMapping.DestinationColumn.Name}]={tempTableAlias}.[{columnMapping.DestinationColumn.Name}]");
                    insertSelectList.Add($"{tempTableAlias}.[" + columnMapping.DestinationColumn.Name + "]");
                }
            }

            string sqlUpdateInsert = "";

            if (updateColumnList.Any())
            {
                var updateColumns = string.Join(",", updateColumnList);
                var sqlUpdateConditions = GetSqlConditions(sqlConditionsColumns, "[t1]", tempTableAlias);

                if (isGroupImport)
                {
                    var destinationGroupId = GetDestinationGroupId(columnMappings);
                    if (destinationGroupId.HasValue && destinationGroupId.Value > 0)
                    {
                        sqlUpdateConditions += $" and [t1].[AccessUserId] <> {destinationGroupId.Value}";
                    }
                }
                sqlUpdateInsert = $"update [t1] set {updateColumns} from {tempTableAlias} INNER JOIN [{mapping.DestinationTable.SqlSchema}].[{destinationTableName}] [t1] ON ({sqlUpdateConditions});";
            }

            if (HasIdentity(mapping))
            {
                sqlUpdateInsert = sqlUpdateInsert + "set identity_insert [" + mapping.DestinationTable.SqlSchema + "].[" + destinationTableName + "] ON;";
            }

            var insertSelect = string.Join(",", insertSelectList);
            var sqlInsertConditions = GetSqlConditions(sqlConditionsColumns, $"[{mapping.DestinationTable.SqlSchema}].[{destinationTableName}]", tempTableAlias);

            sqlUpdateInsert = sqlUpdateInsert + " insert into [" + mapping.DestinationTable.SqlSchema + "].[" + destinationTableName + "] (" + string.Join(",", insertColumns) + ") (" +
                "select " + insertSelect + $" from {tempTableAlias} left outer join [" + mapping.DestinationTable.SqlSchema + "].[" + destinationTableName + "] on " + sqlInsertConditions + " where [" + mapping.DestinationTable.SqlSchema + "].[" + destinationTableName + "].[" + firstKey + "] is null);";

            if (HasIdentity(mapping))
            {
                sqlUpdateInsert = sqlUpdateInsert + "set identity_insert [" + mapping.DestinationTable.SqlSchema + "].[" + destinationTableName + "] OFF;";
            }

            _sqlCommand.CommandText = sqlUpdateInsert;
            var rowsAffected = _sqlCommand.ExecuteNonQuery();
            RowsAffected += rowsAffected;
            if (rowsAffected > 0)
                _logger.Log($"The number of rows affected: {rowsAffected} in the {mapping.DestinationTable.Name} table");
        }
        catch (Exception ex)
        {
            throw GetMoveDataToMainTableException(ex, _sqlCommand, mapping, "TempTableForBulkImport" + mapping.GetId(), insertColumns, tempTableName, destinationTableName);
        }
    }

    private static string GetSqlConditions(List<string> sqlConditionsColumns, string destinationTableAlias, string sourceTableAlias)
        => string.Join(" and ", sqlConditionsColumns.Select(c => $"{destinationTableAlias}.[{c}]={sourceTableAlias}.[{c}]"));

    private int? GetDestinationGroupId(ColumnMappingCollection columnMappings)
    {
        var parentIdMapping = columnMappings.FirstOrDefault(cm => cm.Active && string.Equals(cm.DestinationColumn.Name, "AccessUserParentId", StringComparison.OrdinalIgnoreCase) &&
                        cm.ScriptType == ScriptType.Constant && !string.IsNullOrEmpty(cm.ScriptValue));

        if (parentIdMapping != null)
        {
            int groupId = Converter.ToInt32(parentIdMapping.ScriptValue);
            //Look for existing groups by ID
            bool isExistingGroup = groupId > 0 && ExistingUserGroupIDs.ContainsKey(groupId);
            if (isExistingGroup)
                return groupId;

            //Look for existing groups by Name
            if (ExistingUserGroups.ContainsKey(parentIdMapping.ScriptValue))
            {
                return (int)((DataRow)ExistingUserGroups[parentIdMapping.ScriptValue])["AccessUserID"];
            }
        }
        return null;
    }

    internal new void Close()
    {
        foreach (DataTable table in DataToWrite.Tables)
        {
            string tableName = GetTableNameWithoutPrefix(table.TableName) + "TempTableForBulkImport" + GetPrefixFromTableName(table.TableName);
            _sqlCommand.CommandText = $"if exists (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'{tableName}') AND type in (N'U')) drop table [{tableName}]";
            _sqlCommand.ExecuteNonQuery();
        }
        GroupHierarchyItemsList = null;
        DataToWrite = null;
        _existingUserGroupIDs = null;
        _existingUserGroups = null;
        _existingUsers = null;
        _groupsWhereUsersAreImported = null;
        duplicateRowsHandler = null;
        UpdatedUsers = null;
        _groupsWhereSubGroupsAreImported = null;
    }

    private void UpdateGroupHierarchy(SqlTransaction sqlTransaction)
    {
        _sqlCommand.Transaction = sqlTransaction;
        //Set ExistingGroups to null to get updated current groups
        _existingUserGroups = null;
        StringBuilder updateParentGroupIdSql = new StringBuilder();
        foreach (GroupHierarchyItem item in GroupHierarchyItemsList)
        {
            //Get Parent Group                
            if (ExistingUserGroups.ContainsKey(item.ParentGroupName))
            {
                updateParentGroupIdSql.AppendFormat("update AccessUser set AccessUserParentID = '{0}' where AccessUserUserName = N'{1}'",
                    ((DataRow)ExistingUserGroups[item.ParentGroupName])["AccessUserID"], item.GroupName.Replace("'", "''"));
            }
            else
            {
                //No parent group found
                if (!string.IsNullOrEmpty(item.ParentGroupName))
                    _logger.Log(string.Format("No parent group found for the Group with ID or Name equal to: '{0}'", item.ParentGroupName));
            }
        }
        if (!string.IsNullOrEmpty(updateParentGroupIdSql.ToString()))
        {
            _sqlCommand.CommandText = updateParentGroupIdSql.ToString();
            try
            {
                RowsAffected += _sqlCommand.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Exception: {0} Sql query: {1}", ex.Message, _sqlCommand.CommandText), ex);
            }
        }
    }

    private void UpdateUserGroupRelations(SqlTransaction sqlTransaction, Mapping mapping)
    {
        //Set ExistingGroups to null to get updated current groups
        _existingUserGroups = null;
        _existingUserGroupIDs = null;
        //Get column name for searching the existing users
        string primaryKeyColumn = ColumnNameForSearchingUsers;
        //Check column existence
        if (DataToWrite.Tables[GetTableName("AccessUser", mapping)].Columns.Contains("AccessUserGroups") &&
            ((!UseAutoSearching && DataToWrite.Tables[GetTableName("AccessUser", mapping)].Columns.Contains(primaryKeyColumn) && DataToWrite.Tables[GetTableName("AccessUser", mapping)].Rows.Count > 0) ||
            (UseAutoSearching && SearchingUserColumns.Any(c => UseAutoSearching && DataToWrite.Tables[GetTableName("AccessUser", mapping)].Columns.Contains(c)))
            ))
        {
            bool usersBelongExactlyImportGroups = ImportUsersBelongExactlyImportGroups && MappingIdsWithAaccessUserGroupsColumn.Contains(mapping.GetId());
            bool updateUsersByCustomerNumberMode = IsUpdateUsersByCustomerNumberMode(mapping);

            _sqlCommand.Transaction = sqlTransaction;
            Dictionary<string, List<Tuple<string, string>>> groupUsersRelations = new Dictionary<string, List<Tuple<string, string>>>();

            foreach (DataRow row in DataToWrite.Tables[GetTableName("AccessUser", mapping)].Rows)
            {
                if (row["AccessUserGroups"] != DBNull.Value && !string.IsNullOrEmpty(row["AccessUserGroups"].ToString()))
                {
                    if (!UseAutoSearching && (row[primaryKeyColumn] == DBNull.Value || string.IsNullOrEmpty(row[primaryKeyColumn].ToString())))
                    {
                        continue;
                    }
                    string groups = row["AccessUserGroups"].ToString();
                    if (groups.Contains("@"))
                    {
                        groups = groups.Trim(new char[] { '@' }).Replace("@@", ",");
                    }

                    string[] split = groups.Split(',');
                    for (int i = 0; i < split.Length; i++)
                    {
                        string groupId = split[i];
                        string existingGroupId = string.Empty;
                        //Get Group
                        if (Converter.ToInt32(groupId) > 0)
                        {
                            if (ExistingUserGroupIDs.ContainsKey(groupId))
                            {
                                existingGroupId = groupId.ToString();
                            }
                        }
                        if (string.IsNullOrEmpty(existingGroupId))
                        {
                            if (ExistingUserGroups.ContainsKey(groupId))
                            {
                                existingGroupId = ((DataRow)ExistingUserGroups[groupId])["AccessUserID"].ToString();
                            }
                        }
                        if (!string.IsNullOrEmpty(existingGroupId))
                        {
                            if (!groupUsersRelations.ContainsKey(existingGroupId))
                                groupUsersRelations.Add(existingGroupId, new List<Tuple<string, string>>());
                            if (UseAutoSearching)
                            {
                                foreach (string column in SearchingUserColumns)
                                {
                                    if (DataToWrite.Tables[GetTableName("AccessUser", mapping)].Columns.Contains(column) &&
                                        row[column] != DBNull.Value && !string.IsNullOrEmpty(row[column].ToString()))
                                    {
                                        groupUsersRelations[existingGroupId].Add(new Tuple<string, string>(column, string.Format("\'{0}\'", row[column].ToString().Replace("'", "''"))));
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                groupUsersRelations[existingGroupId].Add(new Tuple<string, string>(primaryKeyColumn, string.Format("\'{0}\'", row[primaryKeyColumn].ToString().Replace("'", "''"))));
                            }
                        }
                        else
                        {
                            if (updateUsersByCustomerNumberMode)
                            {
                                if (row["AccessUserCustomerNumber"] != DBNull.Value && !string.IsNullOrEmpty(row["AccessUserCustomerNumber"].ToString()))
                                    _logger.Log(string.Format("Can't associate the users with CustomerNumber '{0}' with non existing group '{1}'", row["AccessUserCustomerNumber"], groupId));
                            }
                            else if (row["AccessUserUserName"] != DBNull.Value && !string.IsNullOrEmpty(row["AccessUserUserName"].ToString()))
                                _logger.Log(string.Format("Can't associate the user '{0}' with non existing group '{1}'", row["AccessUserUserName"], groupId));
                        }
                    }
                }
            }

            if (_removeMissingGroups || _deleteOnlyFromGroupsThatAreImportedTo || usersBelongExactlyImportGroups)
            {
                Dictionary<Tuple<string, string>, List<string>> userGroupsRelations = new Dictionary<Tuple<string, string>, List<string>>();
                foreach (string groupId in groupUsersRelations.Keys)
                {
                    foreach (Tuple<string, string> userColumnUserValuePair in groupUsersRelations[groupId])
                    {
                        if (!userGroupsRelations.ContainsKey(userColumnUserValuePair))
                            userGroupsRelations.Add(userColumnUserValuePair, new List<string>());
                        if (!userGroupsRelations[userColumnUserValuePair].Contains(groupId))
                            userGroupsRelations[userColumnUserValuePair].Add(groupId);
                    }
                }
                foreach (Tuple<string, string> userColumnUserValuePair in userGroupsRelations.Keys)
                {
                    if (userGroupsRelations[userColumnUserValuePair].Count > 0)
                    {
                        var groupIds = userGroupsRelations[userColumnUserValuePair];
                        _sqlCommand.CommandText = $"insert into AccessUserGroupRelation (AccessUserGroupRelationUserId, AccessUserGroupRelationGroupId) " +
                            $"SELECT a.AccessUserId, g.GroupId FROM AccessUser AS a " +
                            $"CROSS JOIN ( SELECT AccessUserId AS GroupId FROM AccessUser WHERE AccessUserId IN ({string.Join(",", groupIds)}) ) AS g " +
                            $"WHERE {userColumnUserValuePair.Item1} = {userColumnUserValuePair.Item2} " +
                            $"AND NOT EXISTS ( SELECT 1 FROM AccessUserGroupRelation WHERE AccessUserGroupRelationUserId = a.AccessUserId AND AccessUserGroupRelationGroupId = g.GroupId );";
                        //_sqlCommand.CommandText = string.Format("update AccessUser set AccessUserGroups='{0}' where {1} = {2};",
                        //    string.Format("@{0}@", string.Join("@@", userGroupsRelations[userColumnUserValuePair])), userColumnUserValuePair.Item1, userColumnUserValuePair.Item2);
                        try
                        {
                            RowsAffected += _sqlCommand.ExecuteNonQuery();
                        }
                        catch (Exception ex)
                        {
                            throw new Exception(string.Format("Exception: {0} Sql query: {1}", ex.Message, _sqlCommand.CommandText), ex);
                        }
                    }
                }
                userGroupsRelations = null;
            }
            else
            {
                foreach (string groupId in groupUsersRelations.Keys)
                {
                    if (groupUsersRelations[groupId].Count > 0)
                    {
                        Dictionary<string, List<string>> userColumnUsers = new Dictionary<string, List<string>>();
                        foreach (Tuple<string, string> userColumnUserValuePair in groupUsersRelations[groupId])
                        {
                            if (!userColumnUsers.ContainsKey(userColumnUserValuePair.Item1))
                                userColumnUsers.Add(userColumnUserValuePair.Item1, new List<string>());
                            if (!userColumnUsers[userColumnUserValuePair.Item1].Contains(userColumnUserValuePair.Item2))
                                userColumnUsers[userColumnUserValuePair.Item1].Add(userColumnUserValuePair.Item2);
                        }
                        foreach (string column in userColumnUsers.Keys)
                        {
                            string[] usersArr = userColumnUsers[column].ToArray();
                            StringBuilder users = new StringBuilder();
                            for (int i = 0; i < usersArr.Length; i++)
                            {
                                users.AppendFormat(",{0}", usersArr[i]);
                                //split query into smaller parts for not overflow max query size
                                if ((i > 0 && i % 1000 == 0) || i == usersArr.Length - 1)
                                {

                                    _sqlCommand.CommandText = $"insert into AccessUserGroupRelation (AccessUserGroupRelationUserId, AccessUserGroupRelationGroupId) " +
                                        $"SELECT AccessUserId, {groupId} from AccessUser WHERE {column} IN ({users.ToString().TrimStart(new char[] { ',' })}) " +
                                        $"AND NOT EXISTS ( SELECT 1 FROM AccessUserGroupRelation WHERE AccessUserGroupRelationUserId = AccessUserId AND AccessUserGroupRelationGroupId = {groupId} );";
                                    //_sqlCommand.CommandText = string.Format("update AccessUser set AccessUserGroups=IsNull(AccessUserGroups, '')+'@{0}@' where {1} IN ({2}) and (not AccessUserGroups like '%@{0}@%' or AccessUserGroups is null);",
                                    //            groupId, column, users.ToString().TrimStart(new char[] { ',' }));
                                    try
                                    {
                                        RowsAffected += _sqlCommand.ExecuteNonQuery();
                                    }
                                    catch (Exception ex)
                                    {
                                        throw new Exception(string.Format("Can not update AccessUserGroups column. Check if your import data is not making its length more than 255. Exception: {0} Sql query: {1}", ex.Message, _sqlCommand.CommandText), ex);
                                    }
                                    users = new StringBuilder();
                                }
                            }
                            users = null;
                        }
                        userColumnUsers = null;
                    }
                }
            }
            if ((_removeMissingUsers || _deactivateMissingUsers) && _deleteOnlyFromGroupsThatAreImportedTo)
            {
                _groupsWhereUsersAreImported = groupUsersRelations.Keys.ToList();
            }
            groupUsersRelations = null;
        }
    }

    /// <summary>
    /// Updates UserID in UserAddress DataTable with founded UserId in AccessUser table.
    /// Should be executed before MoveDataToMainTable, afer Users import
    /// </summary>
    private void UpdateUserAddressesBeforeMoveToMainTable(SqlTransaction sqlTransaction, Mapping mapping)
    {
        //Get column name for searching the existing users
        string searchColumn = ColumnNameForSearchingUsers;
        //refresh users - take the latest from db
        _existingUsers = null;

        //Check column existence
        if (DataToWrite.Tables[GetTableName("AccessUserAddress", mapping)] != null && DataToWrite.Tables[GetTableName("AccessUserAddress", mapping)].Rows.Count > 0 &&
            ExistingUsers.Rows.Count > 0)
        {
            Dictionary<string, string> processedIds = new();
            _sqlCommand.Transaction = sqlTransaction;
            StringBuilder updateUserIdSql = new StringBuilder();
            foreach (DataRow row in DataToWrite.Tables[GetTableName("AccessUserAddress", mapping)].Rows)
            {
                if (row["AccessUserAddressUserID"] != DBNull.Value && !string.IsNullOrEmpty(row["AccessUserAddressUserID"].ToString()))
                {
                    string sourceUserId = row["AccessUserAddressUserID"].ToString();

                    if (!processedIds.ContainsKey(sourceUserId))
                    {
                        processedIds.Add(sourceUserId, null);
                        //search existing userId by Id and if not found by UserName/column selected in "userKeyField" drop-down list
                        int existingUserId = GetExistingUserID(sourceUserId);

                        if (existingUserId > 0)
                        {
                            if (sourceUserId != existingUserId.ToString())
                            {
                                updateUserIdSql.AppendFormat("update AccessUserAddressTempTableForBulkImport{0} set AccessUserAddressUserID='{1}' where AccessUserAddressUserID='{2}';",
                                        mapping.GetId(), existingUserId.ToString(), sourceUserId);
                            }
                        }
                        else
                        {
                            //User not found, write to log                            
                            if (row.Table.Columns.Contains("AccessUserAddressName") && row["AccessUserAddressName"] != DBNull.Value && !string.IsNullOrEmpty(row["AccessUserAddressName"].ToString()))
                            {
                                _logger.Log(string.Format("Error importing user Address '{0}': No user found with UserID or {1} equal to: '{2}'", row["AccessUserAddressName"], searchColumn, sourceUserId));
                            }
                            else
                            {
                                _logger.Log(string.Format("Error importing user Address: No user found with ID or {0} equal to: '{1}'", searchColumn, sourceUserId));
                            }
                        }
                    }
                }
            }
            //delete relations that do not match user ids                
            updateUserIdSql.Append($"delete from AccessUserAddressTempTableForBulkImport{mapping.GetId()} where AccessUserAddressUserId not in (select CONVERT(varchar(max), AccessUserID) from AccessUser);");

            _sqlCommand.CommandText = updateUserIdSql.ToString();
            try
            {
                _sqlCommand.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Exception: {0} Sql query: {1}", ex.Message, _sqlCommand.CommandText), ex);
            }
        }
    }

    public void SendUserPasswords()
    {
        if (_generateUserPasswords && UsersPasswordsToSend.Count > 0)
        {
            if (!string.IsNullOrEmpty(_emailTemplate))
            {
                var path = $"/UserManagement/UserProvider/{_emailTemplate}";
                if (!System.IO.File.Exists(SystemInformation.MapPath($"/Files/Templates{path}")))
                {
                    _logger.Log($"E-mail template not found: '{path}'. Can't send user generated passwords.");
                    return;
                }
                Rendering.Template tmpl = new Rendering.Template(path);

                string fromEmail = _senderEmail;
                if (!Core.Helpers.StringHelper.IsValidEmailAddress(fromEmail))
                    fromEmail = "noreply@dynamicweb-cms.com";
                string subject = _mailSubject;
                if (string.IsNullOrEmpty(subject))
                    subject = "Login credentials";

                int sent = 0;
                int notSent = 0;

                foreach (UserPassword user in UsersPasswordsToSend)
                {
                    if (Core.Helpers.StringHelper.IsValidEmailAddress(user.Email))
                    {
                        using (MailMessage objMail = new MailMessage())
                        {
                            objMail.IsBodyHtml = true;
                            objMail.Subject = subject;
                            objMail.SubjectEncoding = System.Text.Encoding.UTF8;
                            objMail.From = new MailAddress(fromEmail);
                            objMail.To.Add(user.Email);

                            tmpl.SetTag("DWUsers:User:Username", user.UserName);
                            tmpl.SetTag("DWUsers:User:Password", user.Password);
                            tmpl.SetTag("DWUsers:User:Name", user.Name);
                            tmpl.SetTag("DWUsers:User:Email", user.Email);

                            if (!string.IsNullOrEmpty(user.Country))
                            {
                                tmpl.SetTag("DWUsers:User:Country", user.Country);
                            }

                            objMail.BodyEncoding = System.Text.Encoding.UTF8;
                            objMail.Body = tmpl.Output();

                            sent++;
                            if (!EmailHandler.Send(objMail, true))
                            {
                                notSent++;
                            }
                        }
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(user.UserName))
                            _logger.Log(string.Format("Can't send e-mail to the user '{0}', it is not valid.", user.UserName));
                    }
                }
                if (notSent > 0)
                {
                    if (notSent == sent)
                    {
                        _logger.Log("Emails sending failed. Check EmailHandler logs for details.");
                    }
                    else
                    {
                        _logger.Log("Some emails send failed. Check EmailHandler logs for details.");
                    }
                }
            }
            else
            {
                _logger.Log("E-mail template is not set. Can't send user generated passwords.");
            }
        }
    }

    private DataTable GetExistingGroupsDataTable()
    {
        // create the data adapter 
        SqlDataAdapter groupsDataAdapter = new SqlDataAdapter("select * from AccessUser where AccessUserType IN (2,10,11)",
                                                                             _sqlCommand.Connection);
        if (_sqlCommand.Transaction != null)
            groupsDataAdapter.SelectCommand.Transaction = _sqlCommand.Transaction;
        // create the DataSet 
        new SqlCommandBuilder(groupsDataAdapter);
        DataSet dataSet = new DataSet();
        // fill the DataSet using our DataAdapter 
        groupsDataAdapter.Fill(dataSet);
        return dataSet.Tables[0];
    }

    private DataRow GetExistingUser(Dictionary<string, object> row, Mapping mapping)
    {
        DataRow ret = null;
        if (UseAutoSearching)
        {
            foreach (string column in SearchingUserColumns)
            {
                ret = GetExistingUserBySearchColumn(row, mapping, column);
                if (ret != null)
                {
                    break;
                }
            }
        }
        else
        {
            ret = GetExistingUserBySearchColumn(row, mapping, ColumnNameForSearchingUsers);
        }
        return ret;
    }

    private DataRow GetExistingUser(string searchValue)
    {
        DataRow ret = null;
        if (!string.IsNullOrEmpty(searchValue))
        {
            if (!UseAutoSearching)
            {
                ret = GetExistingUserBySearchColumn(ColumnNameForSearchingUsers, searchValue);
            }
            if (ret == null)
            {
                if (Converter.ToInt32(searchValue) > 0)
                {
                    ret = GetExistingUserBySearchColumn("AccessUserID", searchValue);
                }
                if (ret == null)
                {
                    foreach (string column in SearchingUserColumns)
                    {
                        ret = GetExistingUserBySearchColumn(column, searchValue);
                        if (ret != null)
                            break;
                    }
                }
            }
        }
        return ret;
    }

    private int GetExistingUserID(string searchValue)
    {
        int ret = 0;
        DataRow row = GetExistingUser(searchValue);
        if (row != null)
        {
            ret = Converter.ToInt32(row["AccessUserID"]);
        }
        return ret;
    }

    private DataRow GetExistingUserBySearchColumn(Dictionary<string, object> row, Mapping mapping, string searchColumn)
    {
        DataRow ret = null;
        var columnMappings = mapping.GetColumnMappings();
        var cm = columnMappings.Find(m => string.Compare(m.DestinationColumn.Name, searchColumn, true) == 0);
        if (cm != null)
        {
            string searchValue = GetValue(cm, row);
            ret = GetExistingUserBySearchColumn(searchColumn, searchValue);
        }
        return ret;
    }

    private DataRow GetExistingUserBySearchColumn(string searchColumn, string searchValue)
    {
        DataRow ret = null;
        var users = GetExistingUsersBySearchColumn(searchColumn, searchValue);
        if (users != null && users.Count() > 0)
        {
            ret = users.First();
        }
        return ret;
    }

    private IEnumerable<DataRow> GetExistingUsersBySearchColumn(string searchColumn, string searchValue)
    {
        IEnumerable<DataRow> ret = null;
        if (!string.IsNullOrEmpty(searchValue) && ExistingUsers.Columns[searchColumn] != null)
        {
            int value;
            if (ExistingUsers.Columns[searchColumn].DataType != typeof(int) || int.TryParse(searchValue, out value))
            {
                ret = ExistingUsers.Select(string.Format("{0}='{1}'", searchColumn, searchValue.Replace("'", "''")));
            }
        }
        return ret;
    }

    private IEnumerable<DataRow> GetExistingGroupsBySearchColumn(string searchColumn, string searchValue)
    {
        IEnumerable<DataRow> ret = null;
        if (!string.IsNullOrEmpty(searchValue) && ExistingGroups.Columns[searchColumn] != null)
        {
            int value;
            if (ExistingGroups.Columns[searchColumn].DataType != typeof(int) || int.TryParse(searchValue, out value))
            {
                ret = ExistingGroups.Select(string.Format("{0}='{1}'", searchColumn, searchValue.Replace("'", "''")));
            }
        }
        return ret;
    }

    private DataRow GetExistingGroupBySearchColumn(string searchColumn, string searchValue)
    {
        DataRow ret = null;
        if (!string.IsNullOrEmpty(searchValue) && ExistingGroups.Columns[searchColumn] != null)
        {
            int value;
            if (ExistingGroups.Columns[searchColumn].DataType != typeof(int) || int.TryParse(searchValue, out value))
            {
                // check if group exists
                DataRow[] rows = ExistingGroups.Select(string.Format("{0}='{1}'", searchColumn, searchValue.Replace("'", "''")));
                //find existing group
                if (rows.Length > 0)
                {
                    ret = rows[0];
                }
            }
        }
        return ret;
    }

    private int GetExistingUserOrGroupID(string searchValue)
    {
        int ret = GetExistingUserID(searchValue);
        //user not found, look in groups
        if (ret <= 0)
        {
            DataRow row = null;
            if (!UseAutoSearching)
            {
                row = GetExistingGroupBySearchColumn(ColumnNameForSearchingUsers, searchValue);
            }
            if (row == null)
            {
                if (Converter.ToInt32(searchValue) > 0)
                {
                    row = GetExistingGroupBySearchColumn("AccessUserID", searchValue);
                }
                if (row == null)
                {
                    row = GetExistingGroupBySearchColumn("AccessUserExternalID", searchValue);
                    if (row == null)
                    {
                        foreach (string column in SearchingUserColumns)
                        {
                            row = GetExistingGroupBySearchColumn(column, searchValue);
                            if (row != null)
                                break;
                        }
                    }
                }
            }

            if (row != null)
            {
                ret = Converter.ToInt32(row["AccessUserID"]);
            }
        }
        return ret;
    }

    /// <summary>
    /// Updates UserID in AccessUserSecondaryRelation DataTable with founded UserId in AccessUser table.
    /// Should be executed before MoveDataToMainTable, afer Users import
    /// </summary>
    private void UpdateUserSecondaryRelationBeforeMoveToMainTable(SqlTransaction sqlTransaction, Mapping mapping)
    {
        //Get column name for searching the existing users
        string searchColumn = ColumnNameForSearchingUsers;
        //refresh users - take the latest from db
        _existingUsers = null;

        //Check column existence
        if (DataToWrite.Tables[GetTableName("AccessUserSecondaryRelation", mapping)] != null && DataToWrite.Tables[GetTableName("AccessUserSecondaryRelation", mapping)].Rows.Count > 0 &&
            ExistingUsers.Rows.Count > 0)
        {
            Dictionary<string, int> processedIdUserIdDictionary = new Dictionary<string, int>();
            Dictionary<string, List<int>> processedSecondaryIdUserIdDictionary = new Dictionary<string, List<int>>();
            List<DataRow> rowsToAdd = new List<DataRow>();
            DataTable dataTable = DataToWrite.Tables[GetTableName("AccessUserSecondaryRelation", mapping)];
            foreach (DataRow row in dataTable.Rows)
            {
                if (row["AccessUserSecondaryRelationUserID"] != DBNull.Value && !string.IsNullOrEmpty(row["AccessUserSecondaryRelationUserID"].ToString())
                    && row["AccessUserSecondaryRelationSecondaryUserID"] != DBNull.Value && !string.IsNullOrEmpty(row["AccessUserSecondaryRelationSecondaryUserID"].ToString()))
                {
                    string sourceUserId = row["AccessUserSecondaryRelationUserID"].ToString();
                    int existingUserId = 0;
                    if (!processedIdUserIdDictionary.TryGetValue(sourceUserId, out existingUserId))
                    {
                        existingUserId = GetExistingUserOrGroupID(sourceUserId);
                        if (existingUserId <= 0)
                        {
                            //User not found, write to log                            
                            _logger.Log(string.Format("Error importing user Secondary Relation: No user or group found with ID or {0} equal to: '{1}'", searchColumn, sourceUserId));
                        }
                        processedIdUserIdDictionary.Add(sourceUserId, existingUserId);
                    }
                    if (existingUserId > 0)
                    {
                        string sourceSecondaryUserId = row["AccessUserSecondaryRelationSecondaryUserID"].ToString();
                        List<int> existingSecondaryUserIds = new List<int>();
                        if (!processedSecondaryIdUserIdDictionary.TryGetValue(sourceSecondaryUserId, out existingSecondaryUserIds))
                        {
                            existingSecondaryUserIds = GetExistingSecondaryUsers(sourceSecondaryUserId);
                            if (existingSecondaryUserIds.Count == 0)
                            {
                                _logger.Log(string.Format("Error importing user Secondary Relation: No secondary user or group found with ID or {0} or CustomerNumber equal to: '{1}'", searchColumn, sourceSecondaryUserId));
                            }
                            processedSecondaryIdUserIdDictionary.Add(sourceSecondaryUserId, existingSecondaryUserIds);
                        }

                        if (existingSecondaryUserIds.Count > 0)
                        {
                            row["AccessUserSecondaryRelationUserID"] = existingUserId;
                            row["AccessUserSecondaryRelationSecondaryUserID"] = existingSecondaryUserIds[0];

                            foreach (int existingSecondaryUserId in existingSecondaryUserIds.Skip(1))
                            {
                                DataRow newRow = dataTable.NewRow();
                                newRow["AccessUserSecondaryRelationUserID"] = existingUserId;
                                newRow["AccessUserSecondaryRelationSecondaryUserID"] = existingSecondaryUserId;
                                rowsToAdd.Add(newRow);
                            }
                        }
                    }
                }
            }
            foreach (DataRow row in rowsToAdd)
            {
                dataTable.Rows.Add(row);
            }

            //write table to server temp table
            BulkCopyTable(DataToWrite.Tables[GetTableName("AccessUserSecondaryRelation", mapping)], sqlTransaction);

            //delete relations that do not match user ids
            StringBuilder updateUserIdSql = new StringBuilder();
            updateUserIdSql.Append($"delete from AccessUserSecondaryRelationTempTableForBulkImport{mapping.GetId()} where AccessUserSecondaryRelationUserID not in (select CONVERT(varchar(max), AccessUserID)from AccessUser);");
            updateUserIdSql.Append($"delete from AccessUserSecondaryRelationTempTableForBulkImport{mapping.GetId()} where AccessUserSecondaryRelationSecondaryUserID not in (select CONVERT(varchar(max), AccessUserID)from AccessUser);");

            _sqlCommand.Transaction = sqlTransaction;
            _sqlCommand.CommandText = updateUserIdSql.ToString();
            try
            {
                RowsAffected += _sqlCommand.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Exception: {0} Sql query: {1}", ex.Message, _sqlCommand.CommandText), ex);
            }
        }
    }

    private List<int> GetExistingSecondaryUsers(string secondaryUserId)
    {
        List<int> existingSecondaryUserIds = new List<int>();
        IEnumerable<DataRow> users = null;
        if (!UseAutoSearching)
        {
            users = GetExistingUsersBySearchColumn(ColumnNameForSearchingUsers, secondaryUserId);
        }
        else
        {
            foreach (string column in SearchingUserColumns.Concat(new string[] { "AccessUserExternalID" }))
            {
                users = GetExistingUsersBySearchColumn(column, secondaryUserId);
                if (users != null && users.Count() > 0)
                {
                    break;
                }
            }
        }
        if (users == null || users.Count() == 0)
        {
            if (!UseAutoSearching)
            {
                users = GetExistingGroupsBySearchColumn(ColumnNameForSearchingUsers, secondaryUserId);
            }
            else
            {
                foreach (string column in SearchingUserColumns.Concat(new string[] { "AccessUserExternalID" }))
                {
                    users = GetExistingGroupsBySearchColumn(column, secondaryUserId);
                    if (users != null && users.Count() > 0)
                    {
                        break;
                    }
                }
            }
        }
        if (users != null && users.Count() > 0)
        {
            existingSecondaryUserIds.AddRange(users.Select(u => Converter.ToInt32(u["AccessUserID"])));
            existingSecondaryUserIds = existingSecondaryUserIds.Distinct().ToList();
        }
        return existingSecondaryUserIds;
    }

    private void UpdateSystemFieldValueBeforeMoveToMainTable(SqlTransaction sqlTransaction, Mapping mapping)
    {
        //Get column name for searching the existing users
        string searchColumn = ColumnNameForSearchingUsers;
        //refresh users - take the latest from db
        _existingUsers = null;

        //Check column existence
        if (DataToWrite.Tables[GetTableName("SystemFieldValue", mapping)] != null && DataToWrite.Tables[GetTableName("SystemFieldValue", mapping)].Rows.Count > 0 &&
            ExistingUsers.Rows.Count > 0)
        {
            Dictionary<string, int> processedIdUserIdDictionary = new Dictionary<string, int>();
            foreach (DataRow row in DataToWrite.Tables[GetTableName("SystemFieldValue", mapping)].Rows)
            {
                if (row["SystemFieldValueItemId"] != DBNull.Value && !string.IsNullOrEmpty(row["SystemFieldValueItemId"].ToString()))
                {
                    string sourceUserId = row["SystemFieldValueItemId"].ToString();
                    int existingUserId = 0;
                    if (!processedIdUserIdDictionary.ContainsKey(sourceUserId))
                    {
                        existingUserId = GetExistingUserOrGroupID(sourceUserId);
                        if (existingUserId <= 0)
                        {
                            //User not found, write to log                            
                            _logger.Log(string.Format("Error importing user SystemFieldValue: No user or group found with ID or {0} equal to: '{1}'", searchColumn, sourceUserId));
                        }
                        processedIdUserIdDictionary.Add(sourceUserId, existingUserId);
                    }
                    else
                    {
                        existingUserId = processedIdUserIdDictionary[sourceUserId];
                    }

                    if (existingUserId > 0)
                    {
                        row["SystemFieldValueItemId"] = existingUserId;
                    }
                }
            }

            //write table to server temp table
            BulkCopyTable(DataToWrite.Tables[GetTableName("SystemFieldValue", mapping)], sqlTransaction);
        }
    }

    private void UpdateAccessUserGroupPkColumns(List<Column> columns, Dictionary<string, string> groupDestinationColumnMapping)
    {
        foreach (var column in columns.Where(c => c != null && groupDestinationColumnMapping.ContainsKey(c.Name)))
        {
            column.Name = groupDestinationColumnMapping[column.Name];
        }
    }

    private string GetValue(ColumnMapping? columnMapping, Dictionary<string, object> row)
    {
        string? result = null;
        if (columnMapping != null && (columnMapping.HasScriptWithValue || row.ContainsKey(columnMapping.SourceColumn.Name)))
        {
            switch (columnMapping.ScriptType)
            {
                case ScriptType.None:
                    result = Converter.ToString(row[columnMapping.SourceColumn.Name]);
                    break;
                case ScriptType.Append:
                    result = Converter.ToString(row[columnMapping.SourceColumn.Name]) + columnMapping.ScriptValue;
                    break;
                case ScriptType.Prepend:
                    result = columnMapping.ScriptValue + Converter.ToString(row[columnMapping.SourceColumn.Name]);
                    break;
                case ScriptType.Constant:
                    result = columnMapping.GetScriptValue();
                    break;
                case ScriptType.NewGuid:
                    result = columnMapping.GetScriptValue();
                    break;
            }
        }
        return result;
    }

    //internal void CleanRelationsTables(SqlTransaction transaction)
    //{
    //    _sqlCommand.Transaction = transaction;
    //    _sqlCommand.CommandText = "delete from AccessUserSecondaryRelation where AccessUserSecondaryRelationUserID not in (select AccessUserID from AccessUser);";
    //    _sqlCommand.ExecuteNonQuery();

    //    _sqlCommand.Transaction = transaction;
    //    _sqlCommand.CommandText = "delete from AccessUserSecondaryRelation where AccessUserSecondaryRelationSecondaryUserID not in (select AccessUserID from AccessUser);";
    //    _sqlCommand.ExecuteNonQuery();

    //    _sqlCommand.Transaction = transaction;
    //    _sqlCommand.CommandText = "delete from AccessUserAddress where AccessUserAddressUserId not in (select AccessUserID from AccessUser);";
    //    _sqlCommand.ExecuteNonQuery();            
    //}
}
