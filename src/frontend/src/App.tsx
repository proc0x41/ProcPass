import { useState } from 'react';
import './App.css'
import { CreateVault, UnlockVault, LockVault, GetEntries, AddEntry, UpdateEntry, DeleteEntry } from '../wailsjs/go/main/App'
import { models } from '../wailsjs/go/models'

type ViewState = 'create' | 'unlock' | 'vault';
type Entry = models.Entry;

function App() {
    const [view, setView] = useState<ViewState>('create');

    const [createPassword, setCreatePassword] = useState('');
    const [createConfirm, setCreateConfirm] = useState('');
    const [createError, setCreateError] = useState('');

    const [unlockPassword, setUnlockPassword] = useState('');
    const [unlockError, setUnlockError] = useState('');

    const [entries, setEntries] = useState<Entry[]>([]);
    const [showForm, setShowForm] = useState(false);
    const [editingEntry, setEditingEntry] = useState<Entry | null>(null);
    const [formError, setFormError] = useState('');

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

    const handleCreateVault = async () => {
        if (createPassword.length < 8) {
            setCreateError('Password must be at least 8 characters');
            return;
        }
        if (createPassword !== createConfirm) {
            setCreateError('Passwords do not match');
            return;
        }
        try {
            await CreateVault(createPassword, createConfirm);
            setCreateError('');
            setCreatePassword('');
            setCreateConfirm('');
            setView('unlock');
        } catch (e: any) {
            setCreateError(e.message || 'Failed to create vault');
        }
    };

    const handleUnlockVault = async () => {
        try {
            await UnlockVault(unlockPassword, unlockPassword);
            setUnlockError('');
            setUnlockPassword('');
            loadEntries();
            setView('vault');
        } catch (e: any) {
            setUnlockError(e.message || 'Failed to unlock vault');
        }
    };

    const handleLockVault = async () => {
        try {
            await LockVault();
            setEntries([]);
            setView('unlock');
        } catch (e: any) {
            console.error('Failed to lock vault:', e)
        }
    };

    const loadEntries = async () => {
        try {
            const result = await GetEntries();
            setEntries(result);
        } catch (e: any) {
            console.error('Failed to load entries:', e);
        }
    }

    const handleAddEntry = async () => {
        if (!title.trim()) {
            setFormError('Title is required');
            return;
        }
        try {
            await AddEntry(title, username, password, url, notes);
            resetForm();
            setShowForm(false);
            loadEntries();
        } catch (e: any) {
            setFormError(e.message || 'Failed to ad entry');
        }
    };

    const handleUpdateEntry = async () => {
        if (!editingEntry) return;
        if (!title.trim()) {
            setFormError('Title is required');
            return;
        }
        try {
            await UpdateEntry(editingEntry.id, title, username, password, url, notes);
        } catch (e: any) {
            setFormError(e.message || 'Failed to update entry');
        }
    };

    const handleDeleteEntry = async (id: string) => {
        if (!confirm('Are you sure you want to delete this entry?')) return;
        try {
            await DeleteEntry(id);
            loadEntries();
        } catch (e: any) {
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
        setShowForm(true);
    };

    const cancelForm = () => {
        resetForm();
        setShowForm(false);
    };

    if (view === 'create') {
        return (
            <div>
                <h1>Create New Vault</h1>
                <p className='subtitle'>Set a strong master password to secure your vault</p>
                <div className='form-group'>
                    <label>Master Password</label>
                    <input type="password"
                        value={createPassword}
                        onChange={(e) => setCreatePassword(e.target.value)}
                        placeholder='Enter master password'

                    />
                </div>
                <div className='form-group'>
                    <label>Confirm Password</label>
                    <input
                        type="password"
                        onChange={(e) => setCreateConfirm(e.target.value)}
                        placeholder='Confirm master password'
                    />
                </div>
                {createError && <div className='error'>{createError}</div>}
                <button className='btn primary' onClick={handleCreateVault}>Create Vault</button>
            </div>
        );
    }
}