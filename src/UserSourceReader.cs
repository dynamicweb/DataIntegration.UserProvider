using Dynamicweb.DataIntegration.Integration;
using Dynamicweb.Security.UserManagement;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Globalization;

namespace Dynamicweb.DataIntegration.Providers.UserProvider;

class UserSourceReader : BaseSqlReader
{
    private bool _exportNotExportedUsers;
    private bool _exportNotExportedAfter;
    private DateTime _exportNotExportedAfterDate;

    private static Dictionary<string, string> _tableNameWhereSqlDictionary = new Dictionary<string, string>();
    private static Dictionary<string, SqlParameterCollection> _tableNameSqlParametersDictionary = new Dictionary<string, SqlParameterCollection>();

    public UserSourceReader(Mapping mapping, SqlConnection connection, bool exportNotExportedUsers, bool exportNotExportedAfter, DateTime exportNotExportedAfterDate) : base(mapping, connection)
    {
        _command = new SqlCommand { Connection = connection };
        if (connection.State.ToString() != "Open")
            connection.Open();

        _exportNotExportedUsers = exportNotExportedUsers;
        _exportNotExportedAfter = exportNotExportedAfter;
        _exportNotExportedAfterDate = exportNotExportedAfterDate;

        string whereSql = GetWhereSql();
        if (mapping.SourceTable != null && mapping.SourceTable.Name != "AccessUserSecondaryRelation" && mapping.SourceTable.Name != "SystemFieldValue")
        {
            if (!_tableNameWhereSqlDictionary.ContainsKey(mapping.SourceTable.Name))
                _tableNameWhereSqlDictionary.Add(mapping.SourceTable.Name, whereSql);
            if (!_tableNameSqlParametersDictionary.ContainsKey(mapping.SourceTable.Name))
                _tableNameSqlParametersDictionary.Add(mapping.SourceTable.Name, _command.Parameters);
        }

        LoadReader(whereSql);
    }

    private void LoadReader(string whereSql)
    {
        try
        {
            if (mapping.GetColumnMappings().Count == 0)
                return;

            string sql = "SELECT " + GetColumns() + " FROM  " + GetFromTables();

            if (!string.IsNullOrEmpty(whereSql))
                sql = sql + " WHERE " + whereSql;

            _command.CommandText = sql;
            _reader?.Close();
            _reader = _command.ExecuteReader();
        }
        catch (SqlException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to open SqlSourceReader. Reason: " + ex.Message, ex);
        }
    }

    private string GetWhereSql()
    {
        string conditionalsSql = string.Empty;
        int conditionalCount = 0;
        foreach (MappingConditional conditional in mapping.Conditionals)
        {
            string conditionalSourceColumnName = conditional.SourceColumn.Name;
            if (conditional.SourceColumn.Table != null && string.Compare(conditional.SourceColumn.Table.Name, "AccessUserGroup") == 0)
            {
                conditionalSourceColumnName = UserProvider.GetOriginalColumnNameForGroups(conditional.SourceColumn.Name);
            }

            conditionalsSql = MappingExtensions.GetConditionalSql(conditionalsSql, conditionalSourceColumnName, conditional, conditionalCount);

            if (conditional.SourceColumn.Type == typeof(DateTime))
            {
                _command.Parameters.AddWithValue("@conditional" + conditionalCount, DateTime.Parse(conditional.Condition));
            }
            else
            {
                _command.Parameters.AddWithValue("@conditional" + conditionalCount, conditional.Condition);
            }
            conditionalCount++;
        }

        if (!string.IsNullOrEmpty(conditionalsSql))
            conditionalsSql = conditionalsSql.Substring(0, conditionalsSql.Length - 4);

        if (mapping.SourceTable.Name != "AccessUserSecondaryRelation" && mapping.SourceTable.Name != "SystemFieldValue")
        {
            if (_exportNotExportedUsers)
            {
                string tableName = mapping.SourceTable.Name;
                if (mapping.SourceTable.Name == "AccessUserGroup")
                {
                    tableName = "AccessUser";
                }
                string condition = "";
                if (mapping.SourceTable.Name == "AccessUser")
                {
                    condition = string.Format("[{0}Exported] IS NULL or {0}Exported<{0}UpdatedOn ", tableName);
                }
                else
                {
                    condition = string.Format("[{0}Exported] IS NULL ", tableName);

                }
                conditionalsSql = string.IsNullOrEmpty(conditionalsSql) ? condition : conditionalsSql + " AND " + condition;
            }
            else
            {
                if (_exportNotExportedAfter)
                {
                    string condition = string.Empty;
                    if (mapping.SourceTable.Name == "AccessUserGroup" || mapping.SourceTable.Name == "AccessUser")
                    {
                        condition = string.Format("([AccessUserUpdatedOn] > '{0}' )", _exportNotExportedAfterDate.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
                    }
                    else if (mapping.SourceTable.Name == "AccessUserAddress")
                    {
                        condition = "[AccessUserAddressExported] IS NULL";
                    }
                    conditionalsSql = string.IsNullOrEmpty(conditionalsSql) ? condition : conditionalsSql + " AND " + condition;
                }
            }
        }
        if (mapping.SourceTable.Name == "AccessUser" || mapping.SourceTable.Name == "AccessUserGroup")
        {
            if (!string.IsNullOrEmpty(conditionalsSql))
                conditionalsSql += " AND ";
            if (mapping.SourceTable.Name == "AccessUserGroup")
            {
                conditionalsSql += string.Format("[AccessUser].[AccessUserType] NOT IN ({0})", string.Join(",", User.GetUserTypes(true)));
            }
            else
            {
                conditionalsSql += string.Format("[AccessUser].[AccessUserType] IN ({0})", string.Join(",", User.GetUserTypes(true)));
            }
        }
        if (mapping.SourceTable.Name == "SystemFieldValue")
        {
            if (!string.IsNullOrEmpty(conditionalsSql))
                conditionalsSql += " AND ";
            conditionalsSql += "[SystemFieldValueTableName] = 'AccessUser'";
        }
        return conditionalsSql;
    }

    internal static void UpdateExportedDataInDb(SqlConnection connection)
    {
        if (_tableNameWhereSqlDictionary.Keys.Count > 0)
        {
            DateTime exportedDate = DateTime.Now;

            if (connection.State.ToString() != "Open")
                connection.Open();

            foreach (KeyValuePair<string, string> kvp in _tableNameWhereSqlDictionary)
            {
                SqlCommand command = new SqlCommand { Connection = connection };
                string tableName = kvp.Key;
                if (kvp.Key == "AccessUserGroup")
                {
                    tableName = "AccessUser";
                }
                string sql = string.Format("UPDATE [{0}] SET [{0}Exported] = '{1}'", tableName, exportedDate.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
                if (!string.IsNullOrEmpty(kvp.Value))
                {
                    sql = sql + " WHERE " + kvp.Value;
                }
                command.CommandText = sql;

                if (_tableNameSqlParametersDictionary.ContainsKey(kvp.Key) && _tableNameSqlParametersDictionary[kvp.Key] != null)
                {
                    foreach (SqlParameter p in _tableNameSqlParametersDictionary[kvp.Key])
                        command.Parameters.AddWithValue(p.ParameterName, p.Value);
                }
                try
                {
                    command.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    throw new Exception(string.Format("Exception message: {0} Sql query: {1}", ex.Message, command.CommandText), ex);
                }
            }
            _tableNameWhereSqlDictionary.Clear();
            _tableNameSqlParametersDictionary.Clear();
        }
    }
}
