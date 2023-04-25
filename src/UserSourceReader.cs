using Dynamicweb.DataIntegration.Integration;
using Dynamicweb.DataIntegration.Providers.SqlProvider;
using Dynamicweb.Security.UserManagement;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;

namespace Dynamicweb.DataIntegration.Providers.UserProvider
{
    class UserSourceReader : SqlSourceReader
    {
        private bool _exportNotExportedUsers;
        private bool _exportNotExportedAfter;
        private DateTime _exportNotExportedAfterDate;

        private static Dictionary<string, string> _tableNameWhereSqlDictionary = new Dictionary<string, string>();
        private static Dictionary<string, SqlParameterCollection> _tableNameSqlParametersDictionary = new Dictionary<string, SqlParameterCollection>();

        public UserSourceReader(Mapping mapping, SqlConnection connection, bool exportNotExportedUsers, bool exportNotExportedAfter, DateTime exportNotExportedAfterDate)
        {
            base.mapping = mapping;
            _command = new SqlCommand { Connection = connection };
            if (connection.State.ToString() != "Open")
                connection.Open();

            _exportNotExportedUsers = exportNotExportedUsers;
            _exportNotExportedAfter = exportNotExportedAfter;
            _exportNotExportedAfterDate = exportNotExportedAfterDate;

            string whereSql = GetWhereSql();
            if (base.mapping.SourceTable != null && base.mapping.SourceTable.Name != "AccessUserSecondaryRelation" && base.mapping.SourceTable.Name != "SystemFieldValue")
            {
                if (!_tableNameWhereSqlDictionary.ContainsKey(base.mapping.SourceTable.Name))
                    _tableNameWhereSqlDictionary.Add(base.mapping.SourceTable.Name, whereSql);
                if (!_tableNameSqlParametersDictionary.ContainsKey(base.mapping.SourceTable.Name))
                    _tableNameSqlParametersDictionary.Add(base.mapping.SourceTable.Name, _command.Parameters);
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
                            condition = string.Format("([AccessUserUpdatedOn] > '{0}' )", _exportNotExportedAfterDate.ToString("yyyy-MM-dd HH:mm:ss"));
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

        protected override string GetColumns()
        {
            string result = string.Empty;
            if (mapping.SourceTable != null && (mapping.SourceTable.Name == "AccessUserGroup" || mapping.SourceTable.Name == "AccessUserAddress"))
            {
                if (mapping.SourceTable.Name == "AccessUserGroup")
                {
                    result = mapping.GetColumnMappings().Aggregate("",
                        (current, fm) => (fm.SourceColumn != null) ?
                            current + "[" + UserProvider.GetOriginalColumnNameForGroups(fm.SourceColumn.Name) + "] AS [" + fm.SourceColumn.Name + "], " : current);
                }
                else
                {
                    result = mapping.GetColumnMappings().Aggregate("", (current, fm) => (fm.SourceColumn != null) ?
                        current + (fm.SourceColumn.Name == "AccessUserAddressUserID" ? "CAST([AccessUserAddressUserID] AS NVARCHAR) AS [AccessUserAddressUserID], " : "[" + fm.SourceColumn.Name + "], ")
                        : current);
                }
                result = result.Substring(0, result.Length - 2);
            }
            else
            {
                return base.GetColumns();
            }
            return result;
        }

        protected override string GetFromTables()
        {
            string result = "[" + mapping.SourceTable.SqlSchema + "].[" + mapping.SourceTable.Name + "] ";
            switch (mapping.SourceTable.Name)
            {
                case "AccessUserAddress":
                    result = result + " INNER JOIN [AccessUser] on [AccessUserAddress].[AccessUserAddressUserID] = [AccessUser].[AccessUserID]";
                    break;
                case "AccessUserGroup":
                    result = "[" + mapping.SourceTable.SqlSchema + "].[AccessUser] ";
                    break;
                default:
                    break;
            }
            return result;
        }

        public static void UpdateExportedDataInDb(SqlConnection connection)
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
                    string sql = string.Format("UPDATE [{0}] SET [{0}Exported] = '{1}'", tableName, exportedDate.ToString("yyyy-MM-dd HH:mm:ss"));
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
}
