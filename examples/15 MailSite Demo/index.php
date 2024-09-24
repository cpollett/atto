<?php
require '../../src/MailSite.php';

use seekquarry\atto\MailSite;

//exit(); // you need to comment this line to be able to run this example.

define("MAIL_DB_FILE", "mail_db.txt");

class MailDB
{
    const FOLDER_TYPE = 0;
    const MAIL_TYPE = 1;
    public $users = ['COLS' => ['ID' => 0, 'NAME' => 1, 'USERNAME' => 2],
        'ROWS' =>[[0, 'Chris Pollett', 'cpollett']]];
    public $folders = ['COLS' => ['ID' => 0, 'NAME' => 1, 'USER_ID' => 2,
        'PARENT_ID' => 3],
        'ROWS' =>[[0, 'INBOX', 0, -1]]];
    /*
        Permanent are flags that are user manipulated. Non-permanent are flags
        that might be session-only. For example, a Recent mail means that no
        session has yet been opened that knows about the mail.
     */
    public $flags = ['COLS' => ['ID' => 0, 'NAME' => 2,'PERMANENT' => 3],
        'ROWS' =>[[0, "Answered", true], [1, "Deleted", true],
        [2, "Draft", true], [3, "Flagged", true], [4, "Forwarded", true],
        [5, 0, "Junk", true], [6, "Recent", false], [7, "Seen", true] ] ];
    public $properties = ['COLS' => ['ID' => 0, 'NAME' => 1],
        'ROWS' =>[]];
    public $item_flags = ['COLS' => ['ITEM_ID' => 0, 'ITEM_TYPE',
        'FLAG_ID' => 1], 'ROWS' =>[]];
    public $mail_properties = ['COLS' => ['MAIL_ID' => 0, 'PROPERTY_ID' => 1,
        'VALUE' => 2],
        'ROWS' =>[]];
    public $mails = ['COLS' => ['ID' => 0, 'FOLDER_ID' => 1, 'DATA' => 2],
        'ROWS' =>[]];
    public $domains = ['localhost'];
    public function nextIdTable($table_name)
    {
        if (!in_array($table_name, ["users", "folders", "flags", "properties",
            "mails"])) {
            return false;
        }
        $last_row = count($mail_db->$table_name['ROWS']) - 1;
        $id_col = $mail_db->$table_name['COLS']['ID'];
        $current = (empty($mail_db->$table_name['ROWS'][$last_row][$id_col])) ?
            0 : $mail_db->$table_name['ROWS'][$last_row][$id_col];
        $next_id = $current + 1;
        return $next_id;
    }
    public function deleteTable($columns, $values, $operation, $table_name)
    {
        if (is_string($table_name)) {
            $table = & $this->$table_name;
        } else {
            $table = & $table_name;
        }
        if (!is_array($columns)) {
            $columns = [$columns];
        }
        if (!is_array($values)) {
            $values = [$values];
        }
        if (($num_columns = count($columns)) != count($values)) {
            return false;
        }
        $num_rows = count($table['ROWS']);
        $num_deleted = 0;
        for ($i = 0; $i < $num_rows; $i++ ) {
            $delete = true;
            for($j = 0; $j < $num_columns; $j++) {
                if (!$operation(
                    $table['ROWS'][$i][$table['COLS'][$columns[$j]]],
                    $values[$j], $table['ROWS'][$i]) ) {
                    $delete = false;
                }
            }
            if ($delete) {
                $num_deleted++;
                unset($table['ROWS'][$i]);
            }
        }
        $table['ROWS'] = array_values($table['ROWS']);
        return $num_deleted;
    }
    public function insertTable($row, $table_name)
    {
        if (is_string($table_name)) {
            $table = & $this->$table_name;
        } else {
            $table = & $table_name;
        }
        if (!is_array($row) || count($row) != count($table['COLS'])) {
            return false;
        }
        $table['ROWS'][] = $row;
        return true;
    }
    public function projectTable($column_names, $table_name)
    {
        if (is_string($table_name)) {
            $table = & $this->$table_name;
        } else {
            $table = & $table_name;
        }
        if (is_string($column_names)) {
            $column_names = [$column_names];
        }
        $out = [ 'COLS' => [], 'ROWS' => []];
        $i = 0;
        foreach ($column_names as $name) {
            $out['COLS'][$name] = $i;
            $i++;
        }
        if (empty($table['ROWS'])) {
            return $out;
        }
        foreach ($table['ROWS'] as $row) {
            $out_row = [];
            foreach ($column_names as $name) {
                $out_row[] = $row[$table['COLS'][$name]];
            }
            $out['ROWS'][] = $out_row;
        }
        return $out;
    }
    public function joinTables($join_col_name1, $join_col_name2, $table_name1,
        $table_name2, $project_cols = null)
    {
        if (is_string($table_name1)) {
            $table1 = & $this->$table_name1;
        } else {
            $table1 = & $table_name1;
        }
        if (is_string($table_name2)) {
            $table2 = & $this->$table_name2;
        } else {
            $table2 = & $table_name2;
        }
        $out = [ 'COLS' => [], 'ROWS' => []];
        $i = 0;
        foreach ($table1['COLS'] as $name => $number) {
            $out['COLS'][$name] = $i;
            $i++;
        }
        foreach ($table2['COLS'] as $name => $number) {
            $out['COLS'][$name] = $i;
            $i++;
        }
        if (empty($project_cols)) {
             $out_cols = $table['COLS'];
        } else {
            $out_cols = [];
            $i = 0;
            foreach ($project_cols as $col_name) {
                $out_cols[$col_name] = $i;
                $i++;
            }
        }
        if (empty($table1['ROWS']) || empty($table2['ROWS'])) {
            return $out;
        }
        foreach ($table1['ROWS'] as $row1) {
            foreach ($table2['ROWS'] as $row2) {
                if ($row1[$table1['COLS'][$join_col_name1]] == 
                    $row1[$table2['COLS'][$join_col_name2]]) {
                    $row = array_merge($row1, $row2);
                    if (empty($project_cols)) {
                        $out_row = $row;
                    } else {
                        $out_row = [];
                        foreach ($project_cols as $colname) {
                            $out_row[$out_cols[$colname]] = (empty(
                                $row[$out['COLS'][$colname]])) ? null :
                                $row[$out['COLS'][$colname]];
                        }
                    }
                    $out['ROWS'][] = $out_row;
                }
            }
        }
        if (!empty($project_cols)) {
            $out['COLS'] = $out_cols;
        }
        return $out;
    }
    public function selectTable($column_names, $values, $operation,
        $table_name, $project_cols = [])
    {
        if (is_string($table_name)) {
            $table = & $this->$table_name;
        } else {
            $table = & $table_name;
        }
        if  (!is_array($column_names)) {
            $column_names = [$column_names];
        }
        $num_columns = count($column_names);
        if  (!is_array($values)) {
            $values = [$values];
        }
        if (empty($project_cols)) {
             $out_cols = $table['COLS'];
        } else {
            $out_cols = [];
            $i = 0;
            foreach ($project_cols as $col_name) {
                $out_cols[$col_name] = $i;
                $i++;
            }
        }
        $out = [ 'COLS' => $out_cols, 'ROWS' => []];
        if (empty($table['ROWS'])) {
            return $out;
        }
        foreach ($table['ROWS'] as $row) {
            $add_row = true;
            for ($i = 0; $i < $num_columns; $i++) {
                if (!$operation($row[$table['COLS'][$column_names[$i]]],
                    $values[$i], $row) ) {
                    $add_row = false;
                    break;
                }
            }
            if ($add_row) {
                if (empty($project_cols)) {
                    $out_row = $row;
                } else {
                    $out_row = [];
                    foreach ($project_cols as $colname) {
                        $col_index = $table['COLS'][$colname];
                        $out_row[$out_cols[$colname]] = (empty(
                            $row[$table['COLS'][$colname]])) ? null :
                            $row[$table['COLS'][$colname]];
                    }
                }
                $out['ROWS'][] = $out_row;
            }
        }
        return $out;
    }
    public function updateTable($change_col, $change_val, $select_col,
        $sel_value, $operation, $table_name)
    {
        if (is_string($table_name)) {
            $table = & $this->$table_name;
        } else {
            $table = & $table_name;
        }
        if (empty($table['ROWS']) || empty($table['COLS'][$select_col]) ||
            empty($table['COLS'][$change_col])) {
            return false;
        }
        $num_rows = count($table['ROWS']);
        $sel_col_index = $table['COLS'][$select_col];
        $change_col_index = $table['COLS'][$change_col];
        $num_changed = 0;
        for ($i = 0; $i < $num_rows; $i++) {
            if ($operation($table['ROWS'][$i][$sel_col_index], $sel_value,
                $table['ROWS'][$i]) ) {
                $num_changed++;
                $table['ROWS'][$i][$change_col_index] = $change_val;
            }
        }
        return $num_changed;
    }
    public function countTable($table_name)
    {
        if (is_string($table_name)) {
            $table = & $this->$table_name;
        } else {
            $table = & $table_name;
        }
        return (empty($table['ROWS'])) ? 0 : count($tables['ROWS']);
    }
    public function eq($value1, $value2, $row = null)
    {
        return $value1 == $value2;
    }
    public function leq($value1, $value2, $row = null)
    {
        return $value1 <= $value2;
    }
    public function lt($value1, $value2, $row = null)
    {
        return $value1 < $value2;
    }
    public function getUserId($username)
    {
        $id_table = $this->selectTable('USERNAME', $username,
            [$this, "eq"], "users", ["ID"]);
        $user_id = $id_table['ROWS'][0][0];
        return $user_id;
    }
    public function isLocalUser($name, $domain)
    {
        $users = $this->projectTable("USERNAME", "users");
        if (in_array($name, $users['ROWS']) &&
            in_array($domain, $this->domains)) {
            return true;
        }
        return false;
    }
    public function getUserFolders($username)
    {
        $user_id = $this->getUserId($username);
        return selectTable('USER_ID', $user_id, [$this, "eq"], "folders");
    }
    public function getFolderId($mailbox, $parent_id = -1)
    {
        $mailbox_name_parts = explode("/", $mailbox);
        $num_parent_parts = count($mailbox_name_parts) - 1;
        $current_parent_id = $parent_id;
        for ($i = 0; $i < $num_parent_parts; $i++) {
            $current_parent_id = $this->getSubFolderIdFromName(
                $mailbox_name_parts[$i], $current_parent_id);
            if ($current_parent_id === false) {
                return false;
            }
        }
    }
    public function addFolder($folder_name, $parent_id, $user_name)
    {
        $next_id = $this->nextIdTable("folders");
        $this->insertTable([$next_id, $folder_name, $this->getUserId(
            $user_name), $parent_id], "folders");
    }
    public function removeFolder($folder_id)
    {
        $this->deleteTable("ID", $folder_id, [$this, "eq"], "folders");
        $this->deleteTable("FOLDER_ID", $folder_id, [$this, "eq"], "mails");
    }
    public function getSubFolderIdFromName($name, $parent_id)
    {
        $table_id = @$this->selectTable(
            ['NAME', 'PARENT_ID'], [$name, $parent_id],
            [$this, "eq"], $this->getUserFolders($_SERVER['AUTH_USER']), "ID");
        return (!empty($table_id[0][0])) ? $table_id[0][0] : false;
    }
    public function getMatchingSubFolders($name, $folder_id)
    {
        $magic_string ='zQQz';
        $name = preg_replace("/\*|\%/", 'zQQz', $name);
        $name = preg_quote($name, "/");
        $name = preg_replace("/zQQz/", '.*', $name);
        $name_table = @$this->selectTable('PARENT_ID', $folder_id,
            [$this, "eq"], $this->getUserFolders($_SERVER['AUTH_USER']));
        $out = [ 'COLS' => $user_folders['COLS'], 'ROWS' => [] ];
        if (!empty($name_table['ROWS']) ) {
            foreach ($name_table['ROWS'] as $row) {
                if (preg_match("/$name/", $row['NAME'])) {
                    $out['ROWS'][] = $row;
                }
            }
        }
        return $out;
    }
    public function getUid($i, $folder_id)
    {
        $ids = $this->selectTable("FOLDER_ID", $folder_id, [$this, "eq"],
            "mails", ['ID']);
        if (empty($ids[$i])) {
            return false;
        }
        return $ids[$i][0];
    }
    public function lastMailIdFolder($folder_id, $uid = false)
    {
        $ids = $this->selectTable("FOLDER_ID", $folder_id, [$this, "eq"],
            "mails", ['ID']);
        if (!$uid) {
            return count($ids) - 1;
        }
        $max = -1;
        foreach ($ids as $row) {
            if ($row['ID'] > $max) {
                $max = $row['ID'];
            }
        }
        return $max;
    }
    public function addMail($message, $flags, $time, $folder_id,
        $properties=false)
    {
        $id = $mail_db->nextIdTable("mails");
        $this->mails[] = [$id, $folder_id, $message];
        $flags = array_merge($flags, ['Recent']);
        $this->addFlags([$id], $flags, $folder_id, true);
        if ($properties === false) {
            $this->addProperty($id, $folder_id, "TIME", $time, true);
            $this->addProperty($id, $folder_id, "INTERNAL_TIME", time(), true);
        } else {
            foreach ($properties as $property => $value) {
                $this->addProperty($id, $folder_id, $property, $value, true);
            }
        }
        return $id;
    }
    public function copyMails($sequence_set, $folder_id, $uid = false)
    {
        $this->normalizeSequenceSet($sequence_sets, $folder_id, $uid);
        foreach ($sequence_set  as $set) {
            for ($i = $set[0]; $i <= $set[1]; $i++) {
                $i_uid = ($uid) ? $i : $this->getUid($i, $folder_id);
                $flags = $this->getFlags($i_uid, self::MAIL_TYPE);
                $properties = $this->getProperties($i_uid);
                $mail = $this->getMail($i_uid);
                $add_id = $this->addMail($mail, $flags, 0, $folder_id,
                    $properties);
            }
        }
    }
    public function hasFlag($item_id, $item_type, $flag)
    {
        if ($item_type == MailDB::FOLDER_TYPE && 
            in_array($flag, ['HasChildren', 'HasNoChildren'])) {
            $subfolder_table = @$this->selectTable('PARENT_ID', $item_id,
                [$this, "eq"], $this->getUserFolders($_SERVER['AUTH_USER']));
            if ($this->countTable($subfolder_table) > 0) {
                return ($flag == "HasChildren") ? true : false;
            } else {
                return ($flag == "HasNoChildren") ? true : false;
            }
        }
        $flag_id = $this->getFlagId($flag);
        $rows = $this->selectTable(['ID', 'ITEM_TYPE', 'FLAG_ID'],
            [$item_id, $item_type, $flag_id], "item_flags");
        if (is_array($rows) && count($rows) > 0) {
            return true;
        }
        return false;
    }
    public function getFlags($item_id, $item_type)
    {
        $flags = [];
        if ($item_type == MailDB::FOLDER_TYPE) {
            $subfolder_table = @$this->selectTable('PARENT_ID', $item_id,
                [$this, "eq"], $this->getUserFolders($_SERVER['AUTH_USER']));
            if ($this->countTable($subfolder_table) > 0) {
                $flags[] = "HasChildren";
            } else {
                $flags[] = "HasNoChildren";
            }
        }
        $flag_ids = $this->selectTable(['ID', 'ITEM_TYPE'],
            [$item_id, $item_type], "item_flags", ['FLAG_ID']);
        if (!empty($flag_ids['ROWS'])) {
            foreach ($flag_ids['ROWS'] as $row) {
                $flag_table = $this->selectTable('ID', $row[0],
                    [$this, "eq"], "flags", ["NAME"]);
                $flag = (empty($flag_table['ROWS'][0][0])) ? false :
                    $flag_table['ROWS'][0][0];
                if ($flag) {
                    $flags[] = $flags;
                }
            }
        }
        return $flags;
    }
    public function getMail($mail_id)
    {
    }
    public function getProperties($mail_id)
    {
    }
    public function normalizeSequenceSet($sequence_set, $mailbox_id,
        $uid = false)
    {
        $last_id = $this->lastMailIdFolder($mailbox_id, $uid);
        $out_sequence = [];
        foreach($sequence_set as $set) {
            list($low, $high) = $set;
            if ($high == "*") {
                $high = $last_id;
            }
            $out_sequence[] = [intval($low), intval($high)];
        }
        return $out_sets;
    }
    public function getFlagId($flag_name)
    {
        $flag_table = $this->selectTable('NAME', $flag_name, [$this, "eq"],
            "flags", ["ID"]);
        return (empty($flag_table['ROWS'][0][0])) ? false :
            $flag_table['ROWS'][0][0];
    }
    public function getPropertyId($property_name)
    {
        $property_table = $this->selectTable('NAME', $property_name,
            [$this, "eq"], "properties", ["ID"]);
        return (empty($property_table['ROWS'][0][0])) ? false :
            $property_table['ROWS'][0][0];
    }
    public function addFlags($sequence_set, $flags, $mailbox_id, $uid = false)
    {
        $this->normalizeSequenceSet($sequence_sets, $mailbox_id, $uid);
        foreach ($sequence_set  as $set) {
            for ($i = $set[0]; $i <= $set[1]; $i++) {
                $i_uid = ($uid) ? $i : $this->getUid($i, $mailbox_id);
                foreach ($flags as $flag) {
                    if (!$this->hasFlag($i_uid, self::MAIL_TYPE, $flag)) {
                        $flag_id = $this->getFlagId($flag);
                        $this->insertTable([$i_uid, self::MAIL_TYPE, $flag_id],
                            "item_flags");
                    }
                }
            }
        }
    }
    public function removeAllFlags($sequence_set, $mailbox_id, $uid = false)
    {
        $this->normalizeSequenceSet($sequence_sets, $mailbox_id, $uid);
        foreach ($sequence_set  as $set) {
            for ($i = $set[0]; $i <= $set[1]; $i++) {
                $i_uid = ($uid) ? $i : $this->getUid($i, $mailbox_id);
                $this->deleteTable(["ITEM_ID", "ITEM_TYPE"],
                    [$i_uid, self::MAIL_TYPE], "item_flags");
            }
        }
    }
    public function removeFlags($sequence_set, $flags, $mailbox_id,
        $uid = false)
    {
        $this->normalizeSequenceSet($sequence_sets, $mailbox_id, $uid);
        foreach ($sequence_set  as $set) {
            for ($i = $set[0]; $i <= $set[1]; $i++) {
                $i_uid = ($uid) ? $i : $this->getUid($i, $mailbox_id);
                foreach ($flags as $flag) {
                    if (!$this->hasFlag($i_uid, self::MAIL_TYPE, $flag)) {
                        $flag_id = $this->getFlagId($flag);
                        $this->deleteTable(
                            ["ITEM_ID", "ITEM_TYPE", "FLAG_ID"],
                            [$i_uid, self::MAIL_TYPE, $flag_id],
                            "item_flags");
                    }
                }
            }
        }
    }
    public function addProperty($mail_id, $folder_id,
        $property, $value, $uid = false)
    {
        $property_id = $this->getPropertyId($property);
        $mail_uid = ($uid) ? $mail_id : $this->getUid($mail_id,
            $folder_id);
        $this->insertTable([$mail_uid, $property_id, $value],
            "item_properties");
    }
}
if (file_exists(MAIL_DB_FILE)) {
    $mail_db = @unserialize(file_get_contents(MAIL_DB_FILE));
}
if (empty($mail_db) || get_class($mail_db) != "MailDB") {
    $mail_db = new MailDB();
}
$test = new MailSite();
/*
    A simple MailSite used to demonstrate the main features of the
    MailSite class.
    After commenting the exit() line above, you can run the example
    by typing:
       php index.php
 */
$test->append(function() use ($mail_db, $test) {
    $mailbox = $_SERVER['APPEND_MAILBOX'];
    $mailbox_id = $mail_db->getFolderId($mailbox, $_SERVER['MAILBOX_ID']);
    $flags = $_SERVER['APPEND_FLAGS'];
    $date_time = $_SERVER['APPEND_DATE'];
    $message = $_REQUEST['message'];
    $mail_db->addMail($message, $flags, $time, $mailbox_id);
    $results = [ "RESPONSE" => '', "STATUS" => " OK CREATE completed."];
    return $results;
});
$test->auth(function() {
    $email_parts = explode("@", $_REQUEST['user'], 2);
    if (!empty($email_parts[1]) && $email_parts[1] ==
        $_SERVER['SERVER_NAME']) {
        $_REQUEST['user'] = $email_parts[0];
    }
    if($_REQUEST['user'] == 'cpollett' && $_REQUEST['password'] == 'secret') {
        return true;
    }
    return false;
});
$test->check(function() use($mail_db) {
    file_put_contents(MAIL_DB_FILE, serialize($mail_db));
    $results = [ "RESPONSE" => '', "STATUS" => " OK CREATE completed."];
    return $results;
});
$test->copy(function() use ($mail_db) {
    $sequence_set = $_REQUEST['sequence-set'];
    $mailbox = $_REQUEST['mailbox'];
    $mailbox_id = $mail_db->getFolderId($mailbox);
    if ($mailbox_id === false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO [TRYCREATE] Mailbox doesn't exist: ".
            $_REQUEST['mailbox']] . "";
        return $results;
    }
    $mail_db->copyMails($sequence_set, $mailbox_id, $_REQUEST['UID']);
    $results = [ "RESPONSE" => "",
        "STATUS" => " OK COPY completed."];
    return $results;
});
$test->create(function() use ($mail_db) {
    $parent_id = (empty($_SERVER['MAILBOX_ID'])) ? -1 : $_SERVER['MAILBOX_ID'];
    $mailbox = trim($_REQUEST['mailbox'], "\"'\t ");
    $mailbox_id = $mail_db->getFolderId($mailbox,
        $mail_db->getUserFolders($_SERVER['AUTH_USER']), $parent_id);
    if ($mailbox_id !== false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO Mailbox already exists ".
            $_REQUEST['mailbox']];
        return $results;
    }
    $mail_db->addFolder($mailbox, $parent_id, $_SERVER['AUTH_USER']);
    $results = [ "RESPONSE" => '', "STATUS" => " OK CREATE completed."];
    return $results;
});
$test->data(function() {
//addMail($message, $flags, $time, $folder_id)
        print_r($_REQUEST);
        return true;
    }
);
$test->delete(function() use ($mail_db) {
    $parent_id = (empty($_SERVER['MAILBOX_ID'])) ? -1 : $_SERVER['MAILBOX_ID'];
    $mailbox = trim($_REQUEST['mailbox'], "\"'\t ");
    if ($parent_id == -1 && strtoupper($mailbox) == "INBOX") {
        $results = [ "RESPONSE" => '',
            "STATUS" =>
                " NO INBOX cannot be deleted." ];
        return $results;
    }
    $mailbox_id = $mail_db->getFolderId($mailbox, $parent_id);
    if ($mailbox_id === false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO Mailbox doesn't exist: ".
            $_REQUEST['mailbox']];
        return $results;
    }
    $num_subfolders = $mail_db->countTable(
        $mail_db->getMatchingSubFolders("*", $mailbox_id));
    if ($num_subfolders > 0) {
        $results = [ "RESPONSE" => '',
            "STATUS" =>
                " NO Name \"$mailbox\" has inferior hierarchical names." ];
        return $results;
    }
    $mail_db->removeFolder($mailbox_id);
    $results = [ "RESPONSE" => '',
        "STATUS" => " OK DELETE Completed." ];
    return $results;
});
$test->endIdle(function() use ($mail_db) {
});
$test->examine(function() use ($test) {
    $mailbox = $_REQUEST['mailbox'];
    $out_message = "";
    foreach (["FLAGS", "EXISTS", "UNSEEN", "UIDNEXT", "UIDVALIDITY"] as
        $response_part) {
        $test->trigger($response_part, $mailbox, $out);
        $out_message .= $out;
    }
    $results = [ "RESPONSE" => $out_message,
        "STATUS" => ' OK [READ_ONLY] Examine completed.' ];
    return $results;
});
$test->exists(function() use ($mail_db) {
    $num_mails = $mail_db->countTable("mails");
    $response = "* $num_mails EXISTS\x0D\x0A";
    return $response;
});
$test->expunge(function() use($mail_db) {
    $mail_box = $_SERVER['MAILBOX'];
    $mailbox_id = $_SERVER['MAILBOX_ID'];
    $user_folders = $mail_db->getUserFolders($_SERVER['AUTH_USER']);
    $user_folder_ids = array_column("ID", $user_folders['ROWS']);
    $mail_db->deleteTable("ID", 0, function ($id, $dummy, $row) use ($mail_db,
        $user_folder_ids) {
        if (!in_array($row['FOLDER_ID'], $user_folder_ids)) {
            return false;
        }
        $flags = $mail_db->getFlags($row['ID'], MailDB::MAIL_TYPE);
        return in_array("Deleted", $flags);
    }, "mail");
});
$test->fetch(function() use ($mail_db) {
    $mails = $mail_db->fetchMails($_REQUEST['sequence-set'],
        $_REQUEST['parts_requested'], $_REQUEST['uid']);
    $response = "";
    foreach ($mails as $id => $mail_parts) {
        $response .= "* $id FETCH (";
        $space = "";
        foreach ($mail_parts as $part => $value) {
            $response .= "$space$part ($value)";
            $space = " ";
        }
        $response .= ")";
    }
    $results = [ "RESPONSE" => $response,
        "STATUS" => " OK FETCH completed."];
    return $results;
});
$test->flags(function() use ($mail_db) {
    $flags = $mail_db->projectTable('NAME', "flags");
    $response = "* FLAGS (";
    $flag_list = "";
    $space = "";
    // we'll make all flags permanent
    foreach ($flags as $flag) {
        $flag_list .= "$space\\$flag";
        $space = " ";
    }
    $response .= $flag_list . ")\x0D\x0A";
    $response .= "* OK [PERMANENTFLAGS (" . $flag_list .
        " \*)] Flags permitted.\x0D\x0A";
    return $response;
});
$test->list(function() use ($mail_db) {
    $mailbox = $_REQUEST['mailbox'];
    if ($_REQUEST['reference'] == "" && $mailbox == "" ) {
        $results = [ "RESPONSE" => '* LIST (\Noselect) "/" ""' . "\x0D\x0A",
            "STATUS" => ' OK List completed.' ];
        return $results;
    } else if (!in_array($_REQUEST['reference'], ['""', '"."', "'.'", "."] )) {
        // we haven't implemented references as Mailboxes are in RAM so error
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO can’t list that reference or name." ];
        return $results;
    }
    $user_folders = $mail_db->getUserFolders($_SERVER['AUTH_USER']);
    $current_parent_id = $mail_db->getFolderId($mailbox);
    if ($current_parent_id === false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO can’t list that reference or name." ];
        return $results;
    }
    $sub_folders = $mail_db->getMatchingSubFolders(
        $mailbox_name_parts[$num_parent_parts],
        $current_parent_id, $user_folders);
    $out = "";
    foreach ($sub_folders as $sub_folder) {
        $flags = $mail_db->getFlags($folder_id, MailDB::FOLDER_TYPE);
        $out .= "* LIST (";
        $space = "";
        foreach ($flag as $flag) {
            $out .= "$space\\$flag";
            $space = " ";
        }
        $out .= ") \".\" ". $sub_folder['NAME'] . "\x0D\x0A";
    }
    $results = [ "RESPONSE" => $out, "STATUS" => ' OK List completed.' ];
    return $results;
});
$test->lsub(function() use ($mail_db){
    $mailbox = $_REQUEST['mailbox'];
    if ($_REQUEST['reference'] == "" && $mailbox == "" ) {
        $results = [ "RESPONSE" => '* LSUB (\Noselect) "/" ""' . "\x0D\x0A",
            "STATUS" => ' OK LSUB completed.' ];
        return $results;
    } else if (!in_array($_REQUEST['reference'], ["", "."] )) {
        // we haven't implemented references as Mailboxes are in RAM so error
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO can’t list that reference or name." ];
        return $results;
    }
    $user_folders = $mail_db->getUserFolders($_SERVER['AUTH_USER']);
    $current_parent_id = $mail_db->getFolderId($mailbox);
    if ($current_parent_id === false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO can’t list that reference or name." ];
        return $results;
    }
    $sub_folders = $mail_db->getMatchingSubFolders(
        $mailbox_name_parts[$num_parent_parts],
        $current_parent_id, $user_folders);
    $out = "";
    foreach ($sub_folders as $sub_folder) {
        $flags = $mail_db->getFlags($folder_id, MailDB::FOLDER_TYPE);
        $out .= "* LSUB (";
        $space = "";
        foreach ($flag as $flag) {
            $out .= "$space\\$flag";
            $space = " ";
        }
        $out .= ") \".\" ". $sub_folder['NAME'] . "\x0D\x0A";
    }
    $results = [ "RESPONSE" => $out, "STATUS" => ' OK LSUB completed.' ];
    return $results;
});
$test->mailFrom(function() {
    return true;
});
$test->rcptTo(function() use ($mail_db) {
    list($name, $domain) = explode("@", $_REQUEST['email'], 2);
    $results = [];
    $results[] = $mail_db->isLocalUser($name, $domain);
    if (!empty($_SERVER['AUTH_USER'])) {
        return true;
    }
    return $results[0];
});
$test->recent(function() use ($mail_db) {
    $mailbox = $_REQUEST['mailbox'];
    $mailbox_id = $mail_db->getFolderId($mailbox);
    $mailbox_mails = $mail_db->selectTable("FOLDER_ID", $mailbox_id,
        [$mail_db, "eq"], "mails");
    $recent_id = $mail_db->getFlagId("Recent");
    $flagged_recent = $mail_db->selectTable(["FLAG_ID", "ITEM_TYPE"],
        [$recent_id, MailDB::MAIL_TYPE], [$mail_db, "eq"], "item_flags");
    $num_recent = $mail_db->countTable(
        $mail_db->joinTables("ID", "ITEM_ID", $mailbox_mails,
        $flagged__recent));
    $response = "* $num_recent RECENT\x0D\x0A";
    return $response;
});
$test->rename(function() use ($mail_db) {
    $user_folders = $mail_db->getUserFolders($_SERVER['AUTH_USER']);
    $parent_id = (empty($_SERVER['MAILBOX_ID'])) ? -1 : $_SERVER['MAILBOX_ID'];
    $oldname = $_REQUEST['old_mailbox'];
    $newname = $_REQUEST['new_mailbox'];
    if ($parent_id == -1 && strtoupper($newname) == "INBOX") {
        $results = [ "RESPONSE" => '',
            "STATUS" =>
                "NO INBOX cannot be overwritten." ];
        return $results;
    }
    $new_id = $mail_db->getFolderId($newname, $parent_id);
    if ($new_id !== false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO $newname already exist. "];
        return $results;
    }
    $old_id = $mail_db->getFolderId($oldname, $parent_id);
    if ($old_id === false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO $oldname does not exist."];
        return $results;
    }
    $mail_db->updateTable("NAME", $newname, "ID", $old_id, [$mail_db, "eq"],
        "folders");
    if ($parent_id == -1 && strtoupper($oldname) == "INBOX") {
        // make a new empty inbox if, rename inbox
        $next_id = $mail_db->nextIdTable("folders");
        $user_id = $mail_db->getUserId($_SERVER['AUTH_USER']);
        $mail_db->insertTable([$next_id, "INBOX", $user_id, -1], "folders");
    }
    $results = [ "RESPONSE" => '', "STATUS" => " OK RENAME completed."];
    return $results;
});
$test->search(function() use ($mail_db) {
});
$test->select(function() use ($test, $mail_db) {
    $mailbox = $_REQUEST['mailbox'];
    $mailbox_id = $mail_db->getFolderId($mailbox);
    if ($mailbox_id === false) {
        $results = [ "RESPONSE" => '',
            "STATUS" => " NO Mailbox doesn't exist: ".
            $_REQUEST['mailbox']];
    return $results;
    } else {
        $test->trigger("EXAMINE", $examine_results);
        $_SERVER['MAILBOX'] = $mailbox;
        $_SERVER['MAILBOX_ID'] = $mailbox_id;
        $results = [ "RESPONSE" => $examine_results["RESPONSE"],
            "STATUS" => " OK [READ-WRITE] SELECT completed."];
    }
    return $results;
});
$test->startIdle(function() use ($mail_db) {
});
$test->store(function() use ($mail_db) {
    $sequence_set = $_REQUEST['sequence-set'];
    $flag_list = $_REQUEST['flag-list'];
    $mailbox_id = $_SERVER['MAILBOX_ID'];
    $uid =  $_REQUEST['uid'];
    if (!$_REQUEST['flag-operation']) {
        $mail_db->removeAllFlags($sequence_set, $mailbox_id, $uid);
    }
    if ($_REQUEST['flag-operation'] == "+") {
        $mail_db->addFlags($sequence_set, $flag_list, $mailbox_id, $uid);
    } else if ($_REQUEST['flag-operation'] == "-") {
        $mail_db->removeFlags($sequence_set, $flag_list, $mailbox_id, $uid);
    }
    $response = "";
    if (!$_REQUEST['silent']) {
        foreach ($sequence_set as $range) {
            $low = $range[0];
            $high = $range[1];
            $out = "";
            for ($i = $low; $i <= $high; $i++) {
                if (!$uid) {
                    $i_uid = $mail_db->getUid($i, $mailbox_id);
                }
                $flags = $mail_db->getFlags($i_uid, MailDB::MAIL_ITEM);
                if ($flags) {
                    $out = "* FETCH $i (FLAGS (";
                    $space = "";
                    foreach ($flags as $flag) {
                        $out .= "$space$flag";
                        $space = " ";
                    }
                    $out .= ") )\x0D\x0A";
                }
            }
            $response .= $out;
        }
    }
    $results = [ "RESPONSE" => $response,
        "STATUS" => " OK STORE completed."];
    return $results;
});
$test->subscribe(function() {
    $results = [ "RESPONSE" => '',
        "STATUS" => " BAD Command not implemented."];
    return $results;
});
$test->unseen(function () use ($mail_db) {
    $user_folders = $mail_db->getUserFolders($_SERVER['AUTH_USER']);
    $mailbox = $_REQUEST['mailbox'];
    $mailbox_id = $mail_db->getFolderId($mailbox);
    $mailbox_mails = $mail_db->selectTable("FOLDER_ID", $mailbox_id,
        [$mail_db, "eq"], "mails");
    $seen_id = $mail_db->getFlagId("Seen");
    $num_mails = $mail_db->countTable($mailbox_mails);
    $flagged_seen = $mail_db->selectTable(["FLAG_ID", "ITEM_TYPE"],
        [$seen_id, MailDB::MAIL_TYPE], [$mail_db, "eq"], "item_flags");
    $mailids_seen = $mail_db->joinTables("ID", "ITEM_ID", $mailbox_mails,
        $flagged_seen, ['ITEM_ID']);
    $num_seen = $mail_db->countTable($mailids_seen);
    $num_unseen = max(0, $num_mails - $num_seen);
    $mail_col = $mail_db->mails['COLS']['ID'];
    for ($i = $num_mails - 1; $i >= 0; $i--) {
        if (!in_array($mailbox_mails['ROWS'][$i][$mail_col],
            $mailids_seen['ROWS'][0])) {
            break;
        }
    }
    return "* OK [UNSEEN $num_unseen] Message $i is the first".
        " unseen\x0D\x0A";
});
$test->uidnext(function () use ($mail_db) {
    $next = $mail_db->nextIdTable("mail");
    return "* OK [UIDNEXT $next] Predicted next UID\x0D\x0A";
});
$test->uidvalidity(function () {
    return "* OK [UIDVALIDITY ". \PHP_INT_MAX. "] UIDs valid\x0D\x0A";
});
$test->unsubscribe(function() use ($mail_db) {
    $results = [ "RESPONSE" => '',
        "STATUS" => " BAD Command not implemented."];
    return $results;
});
$test->setTimer(10, function () {
    echo "Current Memory Usage: ".memory_get_usage(). " Peak usage:" .
        memory_get_peak_usage() ."\n";
});
$test->listen("", ['SERVER_CONTEXT' => ['ssl' => [
    'allow_self_signed' => true,
    'local_cert' => 'cert.pem', /* Self-signed cert - in practice get signed
                                    by some certificate authority
                                 */
    'local_pk' => 'key.pem', // Private key
    'verify_peer' => false
]]]);

