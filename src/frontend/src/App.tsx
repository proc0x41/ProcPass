import { useState } from 'react';
import './App.css'
import {
    CreateVault,
    UnlockVault,
    LockVault,
    GetEntries,
    AddEntry,
    UpdateEntry,
    DeleteEntry,
    SelectNewVaultPath,
    SelectVaultPath,
} from '../wailsjs/go/main/App'
import { models } from '../wailsjs/go/models'

type ViewState = 'welcome' | 'create' | 'unlock' | 'vault';
type Entry = models.Entry;

function App() {
    const [view, setView] = useState<ViewState>('welcome');
    const [vaultPath, setVaultPath] = useState('');

    const [createPassword, setCreatePassword] = useState('');
    const [createConfirm, setCreateConfirm] = useState('');
    const [createError, setCreateError] = useState('');

    const [unlockPassword, setUnlockPassword] = useState('');
    const [unlockError, setUnlockError] = useState('');

    const [entries, setEntries] = useState<Entry[]>([]);
    const [showForm, setShowForm] = useState(false);
    const [editingEntry, setEditingEntry] = useState<Entry | null>(null);
    const [formError, setFormError] = useState('');
    const [visiblePasswords, setVisiblePasswords] = useState<Record<string, boolean>>({});

    const [title, setTitle] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [url, setUrl] = useState('');
    const [notes, setNotes] = useState('');

    const resetForm = () => {
        setTitle('');
        setUsername('');
        setPassword('');
        setUrl('');
        setNotes('');
        setEditingEntry(null);
        setFormError('');
    };

    const pickNewVaultPath = async () => {
        try {
            const path = await SelectNewVaultPath();
            if (path) setVaultPath(path);
        } catch (e) {
            console.error('Failed to open save dialog:', e);
        }
    };

    const pickExistingVaultPath = async () => {
        try {
            const path = await SelectVaultPath();
            if (path) setVaultPath(path);
        } catch (e) {
            console.error('Failed to open file dialog:', e);
        }
    };

    const handleCreateVault = async () => {
        if (!vaultPath.trim()) {
            setCreateError('Choose where to save the vault file');
            return;
        }
        if (createPassword.length < 8) {
            setCreateError('Password must be at least 8 characters');
            return;
        }
        if (createPassword !== createConfirm) {
            setCreateError('Passwords do not match');
            return;
        }
        try {
            await CreateVault(vaultPath.trim(), createPassword);
            setCreateError('');
            setCreatePassword('');
            setCreateConfirm('');
            await loadEntries();
            setView('vault');
        } catch (e: any) {
            setCreateError(e?.message || String(e) || 'Failed to create vault');
        }
    };

    const handleUnlockVault = async () => {
        if (!vaultPath.trim()) {
            setUnlockError('Choose a vault file');
            return;
        }
        try {
            await UnlockVault(vaultPath.trim(), unlockPassword);
            setUnlockError('');
            setUnlockPassword('');
            await loadEntries();
            setView('vault');
        } catch (e: any) {
            setUnlockError(e?.message || String(e) || 'Failed to unlock vault');
        }
    };

    const handleLockVault = async () => {
        try {
            await LockVault();
        } catch (e) {
            console.error('Failed to lock vault:', e);
        }
        setEntries([]);
        setVisiblePasswords({});
        cancelForm();
        setView('welcome');
    };

    const loadEntries = async () => {
        try {
            const result = await GetEntries();
            setEntries(result ?? []);
        } catch (e) {
            console.error('Failed to load entries:', e);
        }
    };

    const handleSubmitEntry = async () => {
        if (!title.trim()) {
            setFormError('Title is required');
            return;
        }
        try {
            if (editingEntry) {
                await UpdateEntry(editingEntry.id, title, username, password, url, notes);
            } else {
                await AddEntry(title, username, password, url, notes);
            }
            cancelForm();
            await loadEntries();
        } catch (e: any) {
            setFormError(e?.message || String(e) || 'Failed to save entry');
        }
    };

    const handleDeleteEntry = async (id: string) => {
        if (!window.confirm('Are you sure you want to delete this entry?')) return;
        try {
            await DeleteEntry(id);
            await loadEntries();
        } catch (e) {
            console.error('Failed to delete entry:', e);
        }
    };

    const startEdit = (entry: Entry) => {
        setEditingEntry(entry);
        setTitle(entry.title);
        setUsername(entry.username);
        setPassword(entry.password);
        setUrl(entry.url);
        setNotes(entry.notes);
        setFormError('');
        setShowForm(true);
    };

    const cancelForm = () => {
        resetForm();
        setShowForm(false);
    };

    const togglePasswordVisibility = (id: string) => {
        setVisiblePasswords((prev) => ({ ...prev, [id]: !prev[id] }));
    };

    if (view === 'welcome') {
        return (
            <div className="container centered">
                <h1 className="app-title">ProcPass</h1>
                <p className="subtitle">Local-first, encrypted password manager</p>
                <div className="welcome-actions">
                    <button className="btn primary" onClick={() => setView('create')}>
                        Create New Vault
                    </button>
                    <button className="btn" onClick={() => setView('unlock')}>
                        Open Existing Vault
                    </button>
                </div>
            </div>
        );
    }

    if (view === 'create') {
        return (
            <div className="container centered">
                <h1>Create New Vault</h1>
                <p className="subtitle">Set a strong master password to secure your vault</p>
                <div className="form-group">
                    <label>Vault File</label>
                    <div className="path-row">
                        <input
                            type="text"
                            value={vaultPath}
                            onChange={(e) => setVaultPath(e.target.value)}
                            placeholder="C:\path\to\vault.procpass"
                        />
                        <button className="btn" onClick={pickNewVaultPath}>Browse...</button>
                    </div>
                </div>
                <div className="form-group">
                    <label>Master Password</label>
                    <input
                        type="password"
                        value={createPassword}
                        onChange={(e) => setCreatePassword(e.target.value)}
                        placeholder="Enter master password (min. 8 characters)"
                    />
                </div>
                <div className="form-group">
                    <label>Confirm Password</label>
                    <input
                        type="password"
                        value={createConfirm}
                        onChange={(e) => setCreateConfirm(e.target.value)}
                        placeholder="Confirm master password"
                        onKeyDown={(e) => e.key === 'Enter' && handleCreateVault()}
                    />
                </div>
                {createError && <div className="error">{createError}</div>}
                <div className="actions">
                    <button className="btn" onClick={() => setView('welcome')}>Back</button>
                    <button className="btn primary" onClick={handleCreateVault}>Create Vault</button>
                </div>
            </div>
        );
    }

    if (view === 'unlock') {
        return (
            <div className="container centered">
                <h1>Unlock Vault</h1>
                <p className="subtitle">Enter your master password to open your vault</p>
                <div className="form-group">
                    <label>Vault File</label>
                    <div className="path-row">
                        <input
                            type="text"
                            value={vaultPath}
                            onChange={(e) => setVaultPath(e.target.value)}
                            placeholder="C:\path\to\vault.procpass"
                        />
                        <button className="btn" onClick={pickExistingVaultPath}>Browse...</button>
                    </div>
                </div>
                <div className="form-group">
                    <label>Master Password</label>
                    <input
                        type="password"
                        value={unlockPassword}
                        onChange={(e) => setUnlockPassword(e.target.value)}
                        placeholder="Enter master password"
                        onKeyDown={(e) => e.key === 'Enter' && handleUnlockVault()}
                    />
                </div>
                {unlockError && <div className="error">{unlockError}</div>}
                <div className="actions">
                    <button className="btn" onClick={() => setView('welcome')}>Back</button>
                    <button className="btn primary" onClick={handleUnlockVault}>Unlock</button>
                </div>
            </div>
        );
    }



    return (
        <div className="container vault">
            <header className="vault-header">
                <div>
                    <h1>ProcPass</h1>
                    <p className="vault-path" title={vaultPath}>{vaultPath}</p>
                </div>
                <div className="actions">
                    <button className="btn primary" onClick={() => { resetForm(); setShowForm(true); }}>
                        + New Entry
                    </button>
                    <button className="btn danger" onClick={handleLockVault}>Lock</button>
                </div>
            </header>

            {showForm && (
                <div className="entry-form">
                    <h2>{editingEntry ? 'Edit Entry' : 'New Entry'}</h2>
                    <div className="form-group">
                        <label>Title *</label>
                        <input
                            type="text"
                            value={title}
                            onChange={(e) => setTitle(e.target.value)}
                            placeholder="e.g. GitHub"
                        />
                    </div>
                    <div className="form-group">
                        <label>Username</label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="e.g. john@example.com"
                        />
                    </div>
                    <div className="form-group">
                        <label>Password</label>
                        <input
                            type="text"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Entry password"
                        />
                    </div>
                    <div className="form-group">
                        <label>URL</label>
                        <input
                            type="text"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="https://example.com"
                        />
                    </div>
                    <div className="form-group">
                        <label>Notes</label>
                        <textarea
                            value={notes}
                            onChange={(e) => setNotes(e.target.value)}
                            placeholder="Optional notes"
                            rows={3}
                        />
                    </div>
                    {formError && <div className="error">{formError}</div>}
                    <div className="actions">
                        <button className="btn" onClick={cancelForm}>Cancel</button>
                        <button className="btn primary" onClick={handleSubmitEntry}>
                            {editingEntry ? 'Save Changes' : 'Add Entry'}
                        </button>
                    </div>
                </div>
            )}

            {entries.length === 0 ? (
                <p className="empty-state">No entries yet. Click "+ New Entry" to add your first password.</p>
            ) : (
                <ul className="entry-list">
                    {entries.map((entry) => (
                        <li key={entry.id} className="entry-card">
                            <div className="entry-info">
                                <strong className="entry-title">{entry.title}</strong>
                                {entry.username && <span className="entry-field">{entry.username}</span>}
                                {entry.url && (
                                    <a className="entry-field" href={entry.url} target="_blank" rel="noreferrer">
                                        {entry.url}
                                    </a>
                                )}
                                {entry.password && (
                                    <span className="entry-field password-row">
                                        <code>{visiblePasswords[entry.id] ? entry.password : '••••••••'}</code>
                                        <button
                                            className="btn small"
                                            onClick={() => togglePasswordVisibility(entry.id)}
                                        >
                                            {visiblePasswords[entry.id] ? 'Hide' : 'Show'}
                                        </button>
                                    </span>
                                )}
                                {entry.notes && <span className="entry-field notes">{entry.notes}</span>}
                            </div>
                            <div className="entry-actions">
                                <button className="btn small" onClick={() => startEdit(entry)}>Edit</button>
                                <button className="btn small danger" onClick={() => handleDeleteEntry(entry.id)}>
                                    Delete
                                </button>
                            </div>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}

export default App;
